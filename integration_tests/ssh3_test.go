package integration_tests

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var ssh3Path string
var ssh3ServerPath string

const DEFAULT_URL_PATH = "/ssh3-tests"
const DEFAULT_PROXY_URL_PATH = "/ssh3-tests-proxy"

var serverCommand *exec.Cmd
var serverSessions map[string]*Session = make(map[string]*Session) // bind address to session
var proxyServerCommand *exec.Cmd
var proxyServerSession *Session
var rsaPrivKeyPath string
var ed25519PrivKeyPath string
var ecdsaPrivKeyPath string
var attackerPrivKeyPath string
var username string
var ecdsaUsername string

const serverBind = "127.0.0.1:4433"
const proxyServerBind = "127.0.0.1:4444"

var oldServerBinds map[string]string = map[string]string{
	"v0.1.5-rc1": "127.0.0.1:5000",
	"v0.1.5-rc5": "127.0.0.1:5001",
} // tag version to bind string

func IPv6LoopbackAvailable(addrs []net.Addr) bool {
	for _, addr := range addrs {
		Expect(addr).To(BeAssignableToTypeOf(&net.IPNet{}))
		ip := addr.(*net.IPNet).IP
		if ip.To4() == nil && ip.To16() != nil && ip.IsLoopback() {
			// we found ::1, we can start the test
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

var _ = BeforeSuite(func() {
	var err error
	ssh3Path, err = Build("../cmd/ssh3/main.go")
	Expect(err).ToNot(HaveOccurred())
	if os.Getenv("SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED") == "1" {
		// Tests implying a server will only work on Linux
		// (the server currently only builds on Linux)
		// and the server needs root priviledges, so we only
		// run them is they are enabled explicitly.
		ssh3ServerPath, err = BuildWithEnvironment("../cmd/ssh3-server/main.go", []string{fmt.Sprintf("CGO_ENABLED=%s", os.Getenv("CGO_ENABLED"))})
		Expect(err).ToNot(HaveOccurred())
		serverCommand = exec.Command(ssh3ServerPath,
			"-bind", serverBind,
			"-v",
			"-enable-password-login",
			"-url-path", DEFAULT_URL_PATH,
			"-cert", os.Getenv("CERT_PEM"),
			"-key", os.Getenv("CERT_PRIV_KEY"))
		serverCommand.Env = append(serverCommand.Env, "SSH3_LOG_LEVEL=debug")
		session, err := Start(serverCommand, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())

		serverSessions[serverBind] = session

		for tag, bind := range oldServerBinds {
			gobin, err := os.MkdirTemp("", fmt.Sprintf("ssh3-backwards-compatible-versions-%s", tag))
			Expect(err).ToNot(HaveOccurred())
			cmd := exec.Command("go", "install", fmt.Sprintf("github.com/francoismichel/ssh3/cmd/ssh3-server@%s", tag))
			cmd.Env = os.Environ()
			cmd.Env = append(cmd.Env, fmt.Sprintf("GOBIN=%s", gobin))
			err = cmd.Run()
			Expect(err).ToNot(HaveOccurred())
			serverPath := path.Join(gobin, "ssh3-server")
			Expect(err).ToNot(HaveOccurred())
			backwardsCompatibleServerCommand := exec.Command(serverPath,
				"-bind", bind,
				"-v",
				"-enable-password-login",
				"-url-path", DEFAULT_URL_PATH,
				"-cert", os.Getenv("CERT_PEM"),
				"-key", os.Getenv("CERT_PRIV_KEY"))
			serverCommand.Env = append(backwardsCompatibleServerCommand.Env, "SSH3_LOG_LEVEL=debug")
			session, err = Start(backwardsCompatibleServerCommand, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			serverSessions[bind] = session
		}

		proxyServerCommand = exec.Command(ssh3ServerPath,
			"-bind", proxyServerBind,
			"-v",
			"-enable-password-login",
			"-url-path", DEFAULT_PROXY_URL_PATH,
			"-cert", os.Getenv("CERT_PEM"),
			"-key", os.Getenv("CERT_PRIV_KEY"))
		proxyServerCommand.Env = append(proxyServerCommand.Env, "SSH3_LOG_LEVEL=debug")
		proxyServerSession, err = Start(proxyServerCommand, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())

		serverSessions[proxyServerBind] = proxyServerSession

		rsaPrivKeyPath = os.Getenv("TESTUSER_PRIVKEY")
		ed25519PrivKeyPath = os.Getenv("TESTUSER_ED25519_PRIVKEY")
		ecdsaPrivKeyPath = os.Getenv("TESTUSER_ECDSA_PRIVKEY")
		attackerPrivKeyPath = os.Getenv("ATTACKER_PRIVKEY")
		username = os.Getenv("TESTUSER_USERNAME")
		ecdsaUsername = os.Getenv("ECDSATESTUSER_USERNAME")
		Expect(fileExists(rsaPrivKeyPath)).To(BeTrue())
		Expect(fileExists(attackerPrivKeyPath)).To(BeTrue())
		err = os.WriteFile(fmt.Sprintf("/home/%s/.profile", username), []byte("echo 'hello from .profile'"), 0777)
		Expect(err).ToNot(HaveOccurred())
	}
})

var _ = AfterSuite(func() {
	CleanupBuildArtifacts()
	for _, serverSession := range serverSessions {
		serverSession.Terminate()
	}
})

var _ = Describe("Testing the ssh3 cli", func() {

	Context("Usage", func() {
		It("Displays the help", func() {
			command := exec.Command(ssh3Path, "-h")
			session, err := Start(command, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(session).Should(Exit(0))
			Expect(session.Err.Contents()).To(ContainSubstring("Usage of"))
		})
	})

	Context("With running server", func() {
		BeforeEach(func() {
			if os.Getenv("SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED") != "1" {
				Skip("skipping integration tests")
			}
			Consistently(serverSessions[serverBind], "200ms").ShouldNot(Exit())
		})

		Context("Insecure", func() {
			var clientArgs []string
			getClientArgsWithBind := func(privKeyPath string, bind string, additionalArgs ...string) []string {
				args := []string{
					"-v",
					"-insecure",
					"-privkey", privKeyPath,
				}
				args = append(args, additionalArgs...)
				args = append(args, fmt.Sprintf("%s@%s%s", username, bind, DEFAULT_URL_PATH))
				return args
			}
			getClientArgs := func(privKeyPath string, additionalArgs ...string) []string {
				return getClientArgsWithBind(privKeyPath, serverBind, additionalArgs...)
			}

			Context("Client behaviour", func() {
				It("Should connect using an RSA privkey", func() {
					clientArgs = append(getClientArgs(rsaPrivKeyPath), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				It("Should connect using an RSA privkey through proxy jump", func() {
					clientArgs = append(getClientArgs(rsaPrivKeyPath, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH)), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				for key, val := range oldServerBinds {
					// actually capture the values of key,val, as directly referring them in the code below will only keep the value of the last iteration
					tag, bind := key, val
					When("server version is"+tag+", bind is"+bind, func() {
						It("Should connect using an RSA privkey to old supported server", func() {
							clientArgs = append(getClientArgsWithBind(rsaPrivKeyPath, bind), "echo", "Hello, World!")
							command := exec.Command(ssh3Path, clientArgs...)
							session, err := Start(command, GinkgoWriter, GinkgoWriter)
							Expect(err).ToNot(HaveOccurred())
							Eventually(session).Should(Exit(0))
							Eventually(session).Should(Say("Hello, World!\n"))
						})
					})
				}

				It("Should connect using an ed25519 privkey", func() {
					clientArgs = append(getClientArgs(ed25519PrivKeyPath), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				It("Should connect using an ecdsa privkey", func() {
					// for retrocopatibility integration tests with version 0.1.5, we must perform ecdsa tests
					// for another user as ecdsa is not available on the server on older versions
					savedUsername := username
					username = ecdsaUsername
					clientArgs = append(getClientArgs(ecdsaPrivKeyPath), "echo", "Hello, World!")
					username = savedUsername
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				It("Should return the correct exit status", func() {
					clientArgs0 := append(getClientArgs(rsaPrivKeyPath), "exit", "0")
					clientArgs1 := append(getClientArgs(rsaPrivKeyPath), "exit", "1")
					clientArgs255 := append(getClientArgs(rsaPrivKeyPath), "exit", "255")
					clientArgsMinus1 := append(getClientArgs(rsaPrivKeyPath), "exit", "-1")

					command0 := exec.Command(ssh3Path, clientArgs0...)
					session, err := Start(command0, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))

					command1 := exec.Command(ssh3Path, clientArgs1...)
					session, err = Start(command1, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(1))

					command255 := exec.Command(ssh3Path, clientArgs255...)
					session, err = Start(command255, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(255))

					commandMinus1 := exec.Command(ssh3Path, clientArgsMinus1...)
					session, err = Start(commandMinus1, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(255))
				})

				It("Should signal EOF to the remote command when the local stdin is exhausted", func() {
					// Once the local stdin reaches EOF, the client must half-close the
					// send side of the session channel (QUIC FIN) so that the remote
					// command sees the end of its input; otherwise a remote command
					// reading until EOF (e.g. `cat > file`) never terminates.
					const payloadSize = 8 * 1024 * 1024
					payload := make([]byte, payloadSize)
					_, err := rand.Read(payload)
					Expect(err).ToNot(HaveOccurred())
					expectedHash := sha256.Sum256(payload)

					remoteOutPath := path.Join(os.TempDir(), fmt.Sprintf("ssh3-stdin-eof-%d.bin", os.Getpid()))
					os.Remove(remoteOutPath)
					defer os.Remove(remoteOutPath)

					clientArgs = append(getClientArgs(rsaPrivKeyPath), "cat", ">", remoteOutPath)
					command := exec.Command(ssh3Path, clientArgs...)
					command.Stdin = bytes.NewReader(payload)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())

					// the client must terminate by itself once its stdin is exhausted
					Eventually(session, "10s").Should(Exit(0))

					remoteOut, err := os.ReadFile(remoteOutPath)
					Expect(err).ToNot(HaveOccurred())
					Expect(remoteOut).To(HaveLen(payloadSize))
					Expect(sha256.Sum256(remoteOut)).To(Equal(expectedHash))
				})

				It("Should run the interactive shell in login mode and read .profile", func() {
					clientArgs = getClientArgs(rsaPrivKeyPath)
					command := exec.Command(ssh3Path, clientArgs...)
					stdin, err := command.StdinPipe()
					Expect(err).ToNot(HaveOccurred())
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Consistently(session).ShouldNot(Exit())
					Eventually(session.Out).Should(Say("hello from .profile"))
					_, err = stdin.Write([]byte("exit\n")) // 0x04 = EOT character, closing the bash session
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
				})

				Context("File transfer", func() {
					transferSpec := func(remoteFileName string) string {
						// explicit port and url path: user@host:port/url_path:remote_path
						return fmt.Sprintf("%s@%s%s:%s", username, serverBind, DEFAULT_URL_PATH, remoteFileName)
					}
					// getClientArgs cannot be reused here: it appends its own
					// host operand, and the transfer client takes exactly the
					// -f operands
					transferClientArgs := func(privKeyPath string, operands ...string) []string {
						args := []string{"-v", "-insecure", "-privkey", privKeyPath, "-f"}
						return append(args, operands...)
					}

					It("Should upload and download a file with matching checksums", func() {
						const payloadSize = 8 * 1024 * 1024
						payload := make([]byte, payloadSize)
						_, err := rand.Read(payload)
						Expect(err).ToNot(HaveOccurred())
						expectedHash := sha256.Sum256(payload)

						workspace, err := os.MkdirTemp("", "ssh3-fx-*")
						Expect(err).ToNot(HaveOccurred())
						defer os.RemoveAll(workspace)

						localUpload := path.Join(workspace, "upload.bin")
						Expect(os.WriteFile(localUpload, payload, 0o644)).To(Succeed())

						uploadCommand := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, localUpload, transferSpec("fx-upload.bin"))...)
						uploadOutput, err := uploadCommand.CombinedOutput()
						Expect(err).ToNot(HaveOccurred(), "upload failed: %s", uploadOutput)

						localDownload := path.Join(workspace, "download.bin")
						downloadCommand := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, transferSpec("fx-upload.bin"), localDownload)...)
						downloadOutput, err := downloadCommand.CombinedOutput()
						Expect(err).ToNot(HaveOccurred(), "download failed: %s", downloadOutput)

						downloaded, err := os.ReadFile(localDownload)
						Expect(err).ToNot(HaveOccurred())
						Expect(downloaded).To(HaveLen(payloadSize))
						Expect(sha256.Sum256(downloaded)).To(Equal(expectedHash))

						Expect(exec.Command(ssh3Path, append(getClientArgs(rsaPrivKeyPath), "rm", "fx-upload.bin")...).Run()).To(Succeed())
					})

					It("Should transfer a directory tree recursively with matching checksums", func() {
						workspace, err := os.MkdirTemp("", "ssh3-fx-tree-*")
						Expect(err).ToNot(HaveOccurred())
						defer os.RemoveAll(workspace)

						tree := path.Join(workspace, "tree")
						for _, dir := range []string{"", "sub", "sub/deep", "empty"} {
							Expect(os.MkdirAll(path.Join(tree, dir), 0o755)).To(Succeed())
						}
						manifest := map[string][]byte{}
						for _, file := range []struct {
							relative string
							size     int
						}{
							{relative: "top.bin", size: 1024},
							{relative: "sub/mid.bin", size: 65536},
							{relative: "sub/deep/deep.bin", size: 300},
						} {
							data := make([]byte, file.size)
							_, err := rand.Read(data)
							Expect(err).ToNot(HaveOccurred())
							Expect(os.WriteFile(path.Join(tree, filepath.FromSlash(file.relative)), data, 0o644)).To(Succeed())
							manifest[file.relative] = data
						}

						uploadCommand := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, "-r", tree, transferSpec("fx-tree"))...)
						uploadOutput, err := uploadCommand.CombinedOutput()
						Expect(err).ToNot(HaveOccurred(), "recursive upload failed: %s", uploadOutput)

						localMirror := path.Join(workspace, "mirror")
						downloadCommand := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, "-r", transferSpec("fx-tree"), localMirror)...)
						downloadOutput, err := downloadCommand.CombinedOutput()
						Expect(err).ToNot(HaveOccurred(), "recursive download failed: %s", downloadOutput)

						for relative, data := range manifest {
							mirrored, err := os.ReadFile(path.Join(localMirror, filepath.FromSlash(relative)))
							Expect(err).ToNot(HaveOccurred(), "missing %s in mirror", relative)
							Expect(mirrored).To(Equal(data), "content mismatch for %s", relative)
						}
						_, err = os.Stat(path.Join(localMirror, "empty"))
						Expect(err).ToNot(HaveOccurred(), "empty directory was not transferred")
					})

					It("Should resume an interrupted upload with --continue", func() {
						const payloadSize = 8 * 1024 * 1024
						payload := make([]byte, payloadSize)
						_, err := rand.Read(payload)
						Expect(err).ToNot(HaveOccurred())
						expectedHash := sha256.Sum256(payload)

						workspace, err := os.MkdirTemp("", "ssh3-fx-resume-*")
						Expect(err).ToNot(HaveOccurred())
						defer os.RemoveAll(workspace)

						fullFile := path.Join(workspace, "full.bin")
						Expect(os.WriteFile(fullFile, payload, 0o644)).To(Succeed())
						partialFile := path.Join(workspace, "partial.bin")
						Expect(os.WriteFile(partialFile, payload[:payloadSize/2], 0o644)).To(Succeed())

						// simulate an interrupted transfer: the first half is remote
						partialCommand := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, partialFile, transferSpec("fx-continue.bin"))...)
						_, err = partialCommand.CombinedOutput()
						Expect(err).ToNot(HaveOccurred())

						resumeCommand := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, "--continue", fullFile, transferSpec("fx-continue.bin"))...)
						resumeOutput, err := resumeCommand.CombinedOutput()
						Expect(err).ToNot(HaveOccurred(), "resume failed: %s", resumeOutput)

						backFile := path.Join(workspace, "back.bin")
						_, err = exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, transferSpec("fx-continue.bin"), backFile)...).CombinedOutput()
						Expect(err).ToNot(HaveOccurred())
						downloadedFile, err := os.ReadFile(backFile)
						Expect(err).ToNot(HaveOccurred())
						Expect(downloadedFile).To(HaveLen(payloadSize))
						Expect(sha256.Sum256(downloadedFile)).To(Equal(expectedHash))
					})

					It("Should pass checksum verification on upload", func() {
						workspace, err := os.MkdirTemp("", "ssh3-fx-sum-*")
						Expect(err).ToNot(HaveOccurred())
						defer os.RemoveAll(workspace)

						checksummed := path.Join(workspace, "checksummed.bin")
						data := make([]byte, 1024*1024)
						_, err = rand.Read(data)
						Expect(err).ToNot(HaveOccurred())
						Expect(os.WriteFile(checksummed, data, 0o644)).To(Succeed())

						command := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, "--checksum", checksummed, transferSpec("fx-checksummed.bin"))...)
						output, err := command.CombinedOutput()
						Expect(err).ToNot(HaveOccurred(), "checksummed upload failed: %s", output)
					})
				})

				// It checks that upon executing the client with the -forward-tcp,
				// a TCP socket is indeed well open on the client and is indeed forwarded
				// through the SSH3 connection towards the specified remote IP and port.
				Context("TCP port forwarding", func() {
					testTCPPortForwarding := func(localPort uint16, proxyJump bool, remoteAddr *net.TCPAddr, messageFromClient string, messageFromServer string) {
						localIP := "[::1]"
						if remoteAddr.IP.To4() != nil {
							localIP = "127.0.0.1"
						}
						serverStarted := make(chan struct{})
						// Start a TCP server on the specified remote IP and port
						go func() {
							defer close(serverStarted)
							defer GinkgoRecover()
							listener, err := net.ListenTCP("tcp", remoteAddr)
							Expect(err).ToNot(HaveOccurred())
							defer listener.Close()

							serverStarted <- struct{}{}

							conn, err := listener.Accept()
							Expect(err).ToNot(HaveOccurred())
							defer conn.Close()

							// Read message from client
							buffer := make([]byte, len(messageFromClient))
							_, err = conn.Read(buffer)
							Expect(err).ToNot(HaveOccurred())
							Expect(string(buffer)).To(Equal(messageFromClient))

							// Send message to client
							_, err = conn.Write([]byte(messageFromServer))
							Expect(err).ToNot(HaveOccurred())
							conn.(*net.TCPConn).CloseWrite()

							// Read from the client after receiving the message, assert EOF
							n, err := conn.Read(buffer)
							Expect(err).To(Equal(io.EOF))
							Expect(n).To(Equal(0))
						}()

						Eventually(serverStarted).Should(Receive())
						// Execute the client with TCP port forwarding

						additionalArgs := []string{}
						if proxyJump {
							additionalArgs = append(additionalArgs, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH))
						}
						additionalArgs = append(additionalArgs, "-forward-tcp", fmt.Sprintf("%d/%s@%d", localPort, remoteAddr.IP, remoteAddr.Port))
						clientArgs := getClientArgs(rsaPrivKeyPath, additionalArgs...)
						command := exec.Command(ssh3Path, clientArgs...)
						session, err := Start(command, GinkgoWriter, GinkgoWriter)
						Expect(err).ToNot(HaveOccurred())
						defer session.Terminate()

						// Try to connect to the local forwarded port
						localAddr := fmt.Sprintf("%s:%d", localIP, localPort)
						var conn net.Conn
						// connection refused might happen betwen the time when the process starts and actually listens the socket
						Eventually(func() error {
							var err error
							conn, err = net.Dial("tcp", localAddr)
							return err
						}).ShouldNot(HaveOccurred())
						Expect(err).ToNot(HaveOccurred())
						defer conn.Close()

						// Send message from client
						n, err := conn.Write([]byte(messageFromClient))
						Expect(err).ToNot(HaveOccurred())
						Expect(n).To(Equal(len(messageFromClient)))

						// Close the client-side connection
						conn.(*net.TCPConn).CloseWrite()

						// Read message from server
						buffer := make([]byte, len(messageFromServer))
						conn.SetReadDeadline(time.Now().Add(1 * time.Second))
						n, err = conn.Read(buffer)
						Expect(err).ToNot(HaveOccurred())
						Expect(n).To(Equal(len(messageFromServer)))
						Expect(string(buffer[:n])).To(Equal(messageFromServer))

						// If the messages are correctly exchanged, the forwarding is working as expected
						// Now, check that the TCP conn is well closed and that no additional byte was sent
						n, err = conn.Read(buffer)
						Expect(n).To(Equal(0))
						Expect(err).To(Equal(io.EOF))
					}

					It("works with small messages", func() {
						testTCPPortForwarding(8080, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server")
					})

					It("works through proxy jump", func() {
						testTCPPortForwarding(8080, true, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server")
					})

					It("works with messages larger than a typical MTU", func() {
						rng := rand.New(rand.NewSource(GinkgoRandomSeed()))
						messageFromClient := make([]byte, 20000)
						messageFromServer := make([]byte, 20000)
						n, err := rng.Read(messageFromClient)
						Expect(n).To(Equal(len(messageFromClient)))
						Expect(err).ToNot(HaveOccurred())
						n, err = rng.Read(messageFromServer)
						Expect(n).To(Equal(len(messageFromServer)))
						Expect(err).ToNot(HaveOccurred())
						testTCPPortForwarding(8081, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer))
					})

					It("works with IPv6 addresses", func() {
						// we first have to check whether IPv6 are enabled on that host, it is still often
						// not the case in many Docker containers...
						addrs, err := net.InterfaceAddrs()
						Expect(err).ToNot(HaveOccurred())
						if !IPv6LoopbackAvailable(addrs) {
							Skip("IPv6 not available on this host")
						}
						testTCPPortForwarding(8082, false, &net.TCPAddr{IP: net.ParseIP("::1"), Port: 9091}, "hello from client", "hello from server")
					})
				})
			})

			// It checks that upon executing the client with the -forward-udp,
			// a UDP socket is indeed well open on the client and is indeed forwarded
			// through the SSH3 connection towards the specified remote IP and port.
			Context("UDP port forwarding", func() {
				testUDPPortForwarding := func(localPort uint16, proxyJump bool, remoteAddr *net.UDPAddr, messageFromClient, messageFromServer string) {
					localIP := "[::1]"
					localIPWithoutBrackets := "::1"
					if remoteAddr.IP.To4() != nil {
						localIP = "127.0.0.1"
						localIPWithoutBrackets = localIP
					}
					serverStarted := make(chan struct{})
					// Start a UDP server on the specified remote IP and port
					go func() {
						defer close(serverStarted)
						defer GinkgoRecover()
						conn, err := net.ListenUDP("udp", remoteAddr)
						Expect(err).ToNot(HaveOccurred())
						defer conn.Close()

						serverStarted <- struct{}{}

						buffer := make([]byte, 2*len(messageFromClient))
						n, clientAddr, err := conn.ReadFromUDP(buffer)
						Expect(err).ToNot(HaveOccurred())
						Expect(clientAddr.IP.String()).To(Equal(localIPWithoutBrackets))
						Expect(string(buffer[:n])).To(Equal(messageFromClient))

						// Send message to client
						_, err = conn.WriteToUDP([]byte(messageFromServer), clientAddr)
						Expect(err).ToNot(HaveOccurred())
					}()

					Eventually(serverStarted).Should(Receive())
					// Execute the client with UDP port forwarding

					additionalArgs := []string{}
					if proxyJump {
						additionalArgs = append(additionalArgs, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH))
					}
					additionalArgs = append(additionalArgs, "-forward-udp", fmt.Sprintf("%d/%s@%d", localPort, remoteAddr.IP, remoteAddr.Port))
					clientArgs := getClientArgs(rsaPrivKeyPath, additionalArgs...)
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					defer session.Terminate()

					// Wait for some time to ensure that the client has established the forwarding
					time.Sleep(2 * time.Second)

					// if the remote addr is IPv4 (resp. IPv6), ssh3 listens on the IPv4 (resp. IPv6) loopback
					// Try to connect to the local forwarded port
					localAddr := fmt.Sprintf("%s:%d", localIP, localPort)

					var conn net.Conn
					Eventually(func() error {
						var err error
						conn, err = net.Dial("udp", localAddr)
						return err
					}).ShouldNot(HaveOccurred())
					defer conn.Close()

					// Send message from client
					n, err := conn.Write([]byte(messageFromClient))
					Expect(err).ToNot(HaveOccurred())
					Expect(n).To(Equal(len(messageFromClient)))

					// Read message from server
					buffer := make([]byte, 2*len(messageFromServer))
					conn.SetReadDeadline(time.Now().Add(1 * time.Second))
					n, err = conn.Read(buffer)
					Expect(err).ToNot(HaveOccurred())
					Expect(n).To(Equal(len(messageFromServer)))
					Expect(string(buffer[:n])).To(Equal(messageFromServer))
				}

				It("works with small messages", func() {
					testUDPPortForwarding(8080, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server")
				})

				It("works through proxy jump", func() {
					testUDPPortForwarding(8080, true, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server")
				})

				// Due to current quic-go limitations, the max datagram size is limited to 1200, whatever the real MTU is,
				// so right now we test for 1150 messages and nothing more
				It("works with messages of 1150 bytes", func() {
					rng := rand.New(rand.NewSource(GinkgoRandomSeed()))
					messageFromClient := make([]byte, 1150)
					messageFromServer := make([]byte, 1150)
					n, err := rng.Read(messageFromClient)
					Expect(n).To(Equal(len(messageFromClient)))
					Expect(err).ToNot(HaveOccurred())
					n, err = rng.Read(messageFromServer)
					Expect(n).To(Equal(len(messageFromServer)))
					Expect(err).ToNot(HaveOccurred())
					testUDPPortForwarding(8081, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer))
				})

				It("works with IPv6 addresses", func() {
					// Check whether IPv6 is available on the host
					addrs, err := net.InterfaceAddrs()
					Expect(err).ToNot(HaveOccurred())
					if !IPv6LoopbackAvailable(addrs) {
						Skip("IPv6 not available on this host")
					}
					testUDPPortForwarding(8082, false, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9091}, "hello from client", "hello from server")
				})

			})

			Context("Server behaviour", func() {
				It("Should not grand access to non-authorized identity", func() {
					clientArgs = append(getClientArgs(attackerPrivKeyPath), "echo", "Hello, World!")

					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit())
					Eventually(session).ShouldNot(Exit(0))
					Eventually(string(session.Wait().Err.Contents())).Should(ContainSubstring("unauthorized"))
				})
			})
		})
	})
})
