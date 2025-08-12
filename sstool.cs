using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using WhoIs; // You'll need to find a C# WHOIS library
using Newtonsoft.Json;

namespace ScreenShareTool
{
    public class WebAuthSystem
    {
        private readonly string _authUrl;
        private readonly string _logoPath = "logo.png";

        public WebAuthSystem(string authUrl)
        {
            _authUrl = authUrl;
        }

        public async Task<bool> Login(string username, string password)
        {
            try
            {
                using (var client = new HttpClient())
                {
                    var values = new Dictionary<string, string>
                    {
                        { "username", username },
                        { "password", password }
                    };

                    var content = new FormUrlEncodedContent(values);
                    var response = await client.PostAsync($"{_authUrl}/login.php", content);
                    var responseString = await response.Content.ReadAsStringAsync();
                    dynamic json = JsonConvert.DeserializeObject(responseString);
                    return json.success ?? false;
                }
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> ValidateLicense(string licenseKey)
        {
            try
            {
                using (var client = new HttpClient())
                {
                    var values = new Dictionary<string, string>
                    {
                        { "license_key", licenseKey }
                    };

                    var content = new FormUrlEncodedContent(values);
                    var response = await client.PostAsync($"{_authUrl}/validate_license.php", content);
                    var responseString = await response.Content.ReadAsStringAsync();
                    dynamic json = JsonConvert.DeserializeObject(responseString);
                    return json.valid ?? false;
                }
            }
            catch
            {
                return false;
            }
        }
    }

    public class HackDetector
    {
        private readonly Dictionary<string, List<string>> _knownJavaHacks = new Dictionary<string, List<string>>
        {
            { "Wurst", new List<string> { "Wurst", "wurst" } },
            { "Impact", new List<string> { "Impact", "impact" } },
            { "Aristois", new List<string> { "Aristois", "aristois" } },
            { "Sigma", new List<string> { "Sigma", "sigma" } },
            { "Kami Blue", new List<string> { "Kami", "kami", "blue" } },
            { "Future", new List<string> { "Future", "future" } },
            { "RusherHack", new List<string> { "RusherHack", "rusher" } },
            { "Phobos", new List<string> { "Phobos", "phobos" } }
        };

        private readonly Dictionary<string, List<string>> _knownBedrockHacks = new Dictionary<string, List<string>>
        {
            { "Toolbox", new List<string> { "Toolbox", "toolbox" } },
            { "Horion", new List<string> { "Horion", "horion" } },
            { "Zephyr", new List<string> { "Zephyr", "zephyr" } },
            { "Beton", new List<string> { "Beton", "beton" } }
        };

        public List<Tuple<string, string>> ScanJavaProcesses()
        {
            var detected = new List<Tuple<string, string>>();
            var processes = Process.GetProcesses();

            foreach (var proc in processes)
            {
                try
                {
                    var procName = proc.ProcessName.ToLower();
                    foreach (var hack in _knownJavaHacks)
                    {
                        if (hack.Value.Any(keyword => procName.Contains(keyword.ToLower())))
                        {
                            detected.Add(Tuple.Create(hack.Key, proc.MainModule?.FileName ?? "Unknown"));
                            continue;
                        }

                        var cmdline = GetCommandLine(proc);
                        if (!string.IsNullOrEmpty(cmdline) && 
                            hack.Value.Any(keyword => cmdline.ToLower().Contains(keyword.ToLower())))
                        {
                            detected.Add(Tuple.Create(hack.Key, proc.MainModule?.FileName ?? "Unknown"));
                        }
                    }
                }
                catch { /* Ignore errors */ }
            }

            return detected;
        }

        public List<Tuple<string, string>> ScanBedrockProcesses()
        {
            var detected = new List<Tuple<string, string>>();
            var processes = Process.GetProcesses();

            foreach (var proc in processes)
            {
                try
                {
                    var procName = proc.ProcessName.ToLower();
                    foreach (var hack in _knownBedrockHacks)
                    {
                        if (hack.Value.Any(keyword => procName.Contains(keyword.ToLower())))
                        {
                            detected.Add(Tuple.Create(hack.Key, proc.MainModule?.FileName ?? "Unknown"));
                            continue;
                        }

                        var cmdline = GetCommandLine(proc);
                        if (!string.IsNullOrEmpty(cmdline) && 
                            hack.Value.Any(keyword => cmdline.ToLower().Contains(keyword.ToLower())))
                        {
                            detected.Add(Tuple.Create(hack.Key, proc.MainModule?.FileName ?? "Unknown"));
                        }
                    }
                }
                catch { /* Ignore errors */ }
            }

            return detected;
        }

        public List<Tuple<string, string>> ScanFilesystem(string path)
        {
            var detected = new List<Tuple<string, string>>();
            
            try
            {
                foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                {
                    var fileName = Path.GetFileName(file).ToLower();
                    foreach (var hack in _knownJavaHacks.Concat(_knownBedrockHacks))
                    {
                        if (hack.Value.Any(keyword => fileName.Contains(keyword.ToLower())))
                        {
                            detected.Add(Tuple.Create(hack.Key, file));
                        }
                    }
                }
            }
            catch { /* Ignore errors */ }

            return detected;
        }

        public async Task<List<Tuple<string, string>>> RemoteScan(string ipAddress)
        {
            try
            {
                using (var client = new HttpClient())
                {
                    var response = await client.GetAsync($"http://{ipAddress}:5000/scan");
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        dynamic json = JsonConvert.DeserializeObject(content);
                        // Parse the response into the expected format
                        // This depends on your actual API response structure
                    }
                }
            }
            catch { /* Ignore errors */ }

            return new List<Tuple<string, string>>();
        }

        private string GetCommandLine(Process process)
        {
            using (var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {process.Id}"))
            {
                using (var objects = searcher.Get())
                {
                    return objects.Cast<ManagementBaseObject>().SingleOrDefault()?["CommandLine"]?.ToString();
                }
            }
        }
    }

    public class SecurityScanner
    {
        private HashSet<string> _knownVpnIps;

        public SecurityScanner()
        {
            _knownVpnIps = LoadVpnIps().Result;
        }

        private async Task<HashSet<string>> LoadVpnIps()
        {
            try
            {
                using (var client = new HttpClient())
                {
                    var response = await client.GetStringAsync(
                        "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt");
                    return new HashSet<string>(response.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries));
                }
            }
            catch
            {
                return new HashSet<string>();
            }
        }

        public async Task<bool> CheckVpn(string ip)
        {
            if (_knownVpnIps.Contains(ip))
                return true;

            try
            {
                using (var client = new HttpClient())
                {
                    var response = await client.GetStringAsync($"https://ipapi.co/{ip}/json/");
                    dynamic json = JsonConvert.DeserializeObject(response);
                    return json.proxy == true || json.vpn == true;
                }
            }
            catch
            {
                return false;
            }
        }

        public Dictionary<string, object> ScanUrl(string url)
        {
            try
            {
                var uri = new Uri(url);
                var domain = uri.Host;
                
                // You'll need to find a C# WHOIS library
                var domainInfo = Whois.Lookup(domain);

                var suspiciousKeywords = new[] { "login", "account", "verify", "secure" };
                if (suspiciousKeywords.Any(keyword => url.ToLower().Contains(keyword)))
                {
                    return new Dictionary<string, object>
                    {
                        { "status", "suspicious" },
                        { "details", "Contains phishing keywords" }
                    };
                }

                return new Dictionary<string, object>
                {
                    { "status", "clean" },
                    { "whois", domainInfo }
                };
            }
            catch (Exception e)
            {
                return new Dictionary<string, object>
                {
                    { "status", "error" },
                    { "details", e.Message }
                };
            }
        }
    }

    public class ModernGUI : Form
    {
        private readonly WebAuthSystem _auth;
        private readonly HackDetector _detector;
        private readonly SecurityScanner _scanner;
        private readonly string _logoPath = "logo.png";

        private Panel _contentPanel;
        private TabControl _mainTabControl;

        public ModernGUI(string authUrl)
        {
            _auth = new WebAuthSystem(authUrl);
            _detector = new HackDetector();
            _scanner = new SecurityScanner();

            InitializeLoginScreen();
        }

        private void InitializeLoginScreen()
        {
            this.Text = "ScreenShare Tool";
            this.Size = new Size(1200, 800);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(17, 17, 17);

            // Main panel
            var mainPanel = new Panel
            {
                Size = new Size(400, 500),
                Location = new Point((this.ClientSize.Width - 400) / 2, (this.ClientSize.Height - 500) / 2),
                BackColor = Color.FromArgb(49, 49, 49)
            };
            this.Controls.Add(mainPanel);

            // Logo
            try
            {
                var logo = Image.FromFile(_logoPath);
                var logoPicture = new PictureBox
                {
                    Image = logo,
                    SizeMode = PictureBoxSizeMode.Zoom,
                    Size = new Size(300, 100),
                    Location = new Point(50, 20)
                };
                mainPanel.Controls.Add(logoPicture);
            }
            catch
            {
                var logoPlaceholder = CreatePlaceholderImage(300, 100, "SCREENSHARE\nTOOL", Color.Red);
                var logoPicture = new PictureBox
                {
                    Image = logoPlaceholder,
                    SizeMode = PictureBoxSizeMode.Zoom,
                    Size = new Size(300, 100),
                    Location = new Point(50, 20)
                };
                mainPanel.Controls.Add(logoPicture);
            }

            // Username
            var usernameLabel = new Label
            {
                Text = "Username:",
                ForeColor = Color.White,
                Location = new Point(50, 150),
                Font = new Font("Helvetica", 12)
            };
            mainPanel.Controls.Add(usernameLabel);

            var usernameBox = new TextBox
            {
                Location = new Point(150, 150),
                Size = new Size(200, 30),
                Font = new Font("Helvetica", 12)
            };
            mainPanel.Controls.Add(usernameBox);

            // Password
            var passwordLabel = new Label
            {
                Text = "Password:",
                ForeColor = Color.White,
                Location = new Point(50, 200),
                Font = new Font("Helvetica", 12)
            };
            mainPanel.Controls.Add(passwordLabel);

            var passwordBox = new TextBox
            {
                Location = new Point(150, 200),
                Size = new Size(200, 30),
                Font = new Font("Helvetica", 12),
                PasswordChar = '*'
            };
            mainPanel.Controls.Add(passwordBox);

            // License
            var licenseLabel = new Label
            {
                Text = "License Key:",
                ForeColor = Color.White,
                Location = new Point(50, 250),
                Font = new Font("Helvetica", 12)
            };
            mainPanel.Controls.Add(licenseLabel);

            var licenseBox = new TextBox
            {
                Location = new Point(150, 250),
                Size = new Size(200, 30),
                Font = new Font("Helvetica", 12)
            };
            mainPanel.Controls.Add(licenseBox);

            // Login button
            var loginButton = new Button
            {
                Text = "LOGIN",
                BackColor = Color.Red,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(200, 40),
                Location = new Point(100, 320),
                Font = new Font("Helvetica", 12)
            };
            loginButton.FlatAppearance.BorderSize = 0;
            loginButton.Click += async (sender, e) => 
            {
                if (string.IsNullOrEmpty(usernameBox.Text) || 
                    string.IsNullOrEmpty(passwordBox.Text) || 
                    string.IsNullOrEmpty(licenseBox.Text))
                {
                    MessageBox.Show("All fields are required!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (!await _auth.ValidateLicense(licenseBox.Text))
                {
                    MessageBox.Show("Invalid license key!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                if (await _auth.Login(usernameBox.Text, passwordBox.Text))
                {
                    InitializeMainMenu();
                }
                else
                {
                    MessageBox.Show("Invalid credentials!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            };
            mainPanel.Controls.Add(loginButton);

            // Version label
            var versionLabel = new Label
            {
                Text = "v2.0.1 | SSTOOL ScreenShare Team",
                ForeColor = Color.Gray,
                Location = new Point(100, 450),
                Font = new Font("Helvetica", 10)
            };
            mainPanel.Controls.Add(versionLabel);
        }

        private void InitializeMainMenu()
        {
            this.Controls.Clear();
            this.BackColor = Color.FromArgb(17, 17, 17);

            // Top bar
            var topBar = new Panel
            {
                Size = new Size(this.ClientSize.Width, 70),
                Dock = DockStyle.Top,
                BackColor = Color.FromArgb(49, 49, 49)
            };
            this.Controls.Add(topBar);

            // Logo in top bar
            try
            {
                var logo = Image.FromFile(_logoPath);
                var logoPicture = new PictureBox
                {
                    Image = logo,
                    SizeMode = PictureBoxSizeMode.Zoom,
                    Size = new Size(150, 50),
                    Location = new Point(20, 10)
                };
                topBar.Controls.Add(logoPicture);
            }
            catch
            {
                var logoPlaceholder = CreatePlaceholderImage(150, 50, "SL", Color.Red);
                var logoPicture = new PictureBox
                {
                    Image = logoPlaceholder,
                    SizeMode = PictureBoxSizeMode.Zoom,
                    Size = new Size(150, 50),
                    Location = new Point(20, 10)
                };
                topBar.Controls.Add(logoPicture);
            }

            // Logout button
            var logoutButton = new Button
            {
                Text = "LOGOUT",
                BackColor = Color.Red,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(100, 30),
                Location = new Point(this.ClientSize.Width - 120, 20),
                Font = new Font("Helvetica", 10)
            };
            logoutButton.FlatAppearance.BorderSize = 0;
            logoutButton.Click += (sender, e) => InitializeLoginScreen();
            topBar.Controls.Add(logoutButton);

            // Main content area
            var mainPanel = new Panel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(20),
                BackColor = Color.FromArgb(17, 17, 17)
            };
            this.Controls.Add(mainPanel);

            // Side menu
            var sideMenu = new Panel
            {
                Width = 200,
                Dock = DockStyle.Left,
                BackColor = Color.FromArgb(49, 49, 49)
            };
            mainPanel.Controls.Add(sideMenu);

            // Menu buttons
            var menuItems = new[]
            {
                "Java Scan",
                "Bedrock Scan",
                "URL Scanner",
                "VPN Detection",
                "Remote Scan",
                "Settings"
            };

            for (int i = 0; i < menuItems.Length; i++)
            {
                var button = new Button
                {
                    Text = menuItems[i],
                    BackColor = Color.Red,
                    ForeColor = Color.White,
                    FlatStyle = FlatStyle.Flat,
                    Size = new Size(180, 40),
                    Location = new Point(10, 10 + i * 50),
                    Font = new Font("Helvetica", 10)
                };
                button.FlatAppearance.BorderSize = 0;
                
                switch (i)
                {
                    case 0: button.Click += (sender, e) => ShowJavaScan(); break;
                    case 1: button.Click += (sender, e) => ShowBedrockScan(); break;
                    case 2: button.Click += (sender, e) => ShowUrlScanner(); break;
                    case 3: button.Click += (sender, e) => ShowVpnDetection(); break;
                    case 4: button.Click += (sender, e) => ShowRemoteScan(); break;
                    case 5: button.Click += (sender, e) => ShowSettings(); break;
                }
                
                sideMenu.Controls.Add(button);
            }

            // Content panel
            _contentPanel = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(34, 34, 34)
            };
            mainPanel.Controls.Add(_contentPanel);

            // Show dashboard by default
            ShowDashboard();
        }

        private void ShowDashboard()
        {
            _contentPanel.Controls.Clear();

            var title = new Label
            {
                Text = "DASHBOARD",
                ForeColor = Color.Red,
                Font = new Font("Helvetica", 16, FontStyle.Bold),
                Location = new Point(20, 20),
                AutoSize = true
            };
            _contentPanel.Controls.Add(title);

            // Stats
            var stats = new[]
            {
                ("Total Scans", "1,248"),
                ("Hacks Detected", "387"),
                ("VPNs Blocked", "156"),
                ("Active Licenses", "42")
            };

            var statsPanel = new FlowLayoutPanel
            {
                Location = new Point(20, 60),
                Size = new Size(_contentPanel.Width - 40, 100),
                BackColor = Color.Transparent
            };
            _contentPanel.Controls.Add(statsPanel);

            foreach (var stat in stats)
            {
                var statPanel = new Panel
                {
                    Size = new Size(200, 80),
                    Margin = new Padding(10),
                    BackColor = Color.FromArgb(50, 50, 50)
                };

                var statLabel = new Label
                {
                    Text = stat.Item1,
                    ForeColor = Color.Gray,
                    Location = new Point(10, 10),
                    AutoSize = true
                };
                statPanel.Controls.Add(statLabel);

                var statValue = new Label
                {
                    Text = stat.Item2,
                    ForeColor = Color.White,
                    Font = new Font("Helvetica", 14, FontStyle.Bold),
                    Location = new Point(10, 30),
                    AutoSize = true
                };
                statPanel.Controls.Add(statValue);

                statsPanel.Controls.Add(statPanel);
            }

            // Quick actions
            var actionsLabel = new Label
            {
                Text = "Quick Actions",
                ForeColor = Color.White,
                Font = new Font("Helvetica", 12),
                Location = new Point(20, 180),
                AutoSize = true
            };
            _contentPanel.Controls.Add(actionsLabel);

            var actionsPanel = new FlowLayoutPanel
            {
                Location = new Point(20, 210),
                Size = new Size(_contentPanel.Width - 40, 50),
                BackColor = Color.Transparent
            };
            _contentPanel.Controls.Add(actionsPanel);

            var quickActions = new[]
            {
                ("Scan Now", (Action)ShowJavaScan),
                ("Check VPN", ShowVpnDetection),
                ("URL Scan", ShowUrlScanner)
            };

            foreach (var action in quickActions)
            {
                var button = new Button
                {
                    Text = action.Item1,
                    BackColor = Color.Red,
                    ForeColor = Color.White,
                    FlatStyle = FlatStyle.Flat,
                    Size = new Size(120, 40),
                    Font = new Font("Helvetica", 10)
                };
                button.FlatAppearance.BorderSize = 0;
                button.Click += (sender, e) => action.Item2();
                actionsPanel.Controls.Add(button);
            }
        }

        private void ShowJavaScan()
        {
            _contentPanel.Controls.Clear();

            var title = new Label
            {
                Text = "JAVA EDITION SCAN",
                ForeColor = Color.Red,
                Font = new Font("Helvetica", 16, FontStyle.Bold),
                Location = new Point(20, 20),
                AutoSize = true
            };
            _contentPanel.Controls.Add(title);

            var scanButton = new Button
            {
                Text = "START SCAN",
                BackColor = Color.Red,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(150, 40),
                Location = new Point(20, 60),
                Font = new Font("Helvetica", 10)
            };
            scanButton.FlatAppearance.BorderSize = 0;
            scanButton.Click += (sender, e) => PerformJavaScan();
            _contentPanel.Controls.Add(scanButton);

            var resultsBox = new RichTextBox
            {
                Location = new Point(20, 110),
                Size = new Size(_contentPanel.Width - 40, _contentPanel.Height - 140),
                BackColor = Color.FromArgb(34, 34, 34),
                ForeColor = Color.White,
                Font = new Font("Consolas", 10),
                ReadOnly = true
            };
            _contentPanel.Controls.Add(resultsBox);

            void PerformJavaScan()
            {
                resultsBox.Clear();
                var detected = _detector.ScanJavaProcesses();

                if (detected.Any())
                {
                    resultsBox.SelectionColor = Color.FromArgb(255, 85, 85);
                    resultsBox.AppendText("=== DETECTED JAVA HACKS ===\n\n");

                    foreach (var (hack, path) in detected)
                    {
                        resultsBox.SelectionColor = Color.FromArgb(255, 85, 85);
                        resultsBox.AppendText($"[!] {hack}\n");
                        resultsBox.SelectionColor = Color.White;
                        resultsBox.AppendText($"    Path: {path}\n\n");
                    }
                }
                else
                {
                    resultsBox.SelectionColor = Color.FromArgb(85, 255, 85);
                    resultsBox.AppendText("No Java hacks detected.\n");
                }
            }
        }

        private void ShowBedrockScan()
        {
            _contentPanel.Controls.Clear();

            var title = new Label
            {
                Text = "BEDROCK EDITION SCAN",
                ForeColor = Color.Red,
                Font = new Font("Helvetica", 16, FontStyle.Bold),
                Location = new Point(20, 20),
                AutoSize = true
            };
            _contentPanel.Controls.Add(title);

            var scanButton = new Button
            {
                Text = "START SCAN",
                BackColor = Color.Red,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(150, 40),
                Location = new Point(20, 60),
                Font = new Font("Helvetica", 10)
            };
            scanButton.FlatAppearance.BorderSize = 0;
            scanButton.Click += (sender, e) => PerformBedrockScan();
            _contentPanel.Controls.Add(scanButton);

            var resultsBox = new RichTextBox
            {
                Location = new Point(20, 110),
                Size = new Size(_contentPanel.Width - 40, _contentPanel.Height - 140),
                BackColor = Color.FromArgb(34, 34, 34),
                ForeColor = Color.White,
                Font = new Font("Consolas", 10),
                ReadOnly = true
            };
            _contentPanel.Controls.Add(resultsBox);

            void PerformBedrockScan()
            {
                resultsBox.Clear();
                var detected = _detector.ScanBedrockProcesses();

                if (detected.Any())
                {
                    resultsBox.SelectionColor = Color.FromArgb(255, 85, 85);
                    resultsBox.AppendText("=== DETECTED BEDROCK HACKS ===\n\n");

                    foreach (var (hack, path) in detected)
                    {
                        resultsBox.SelectionColor = Color.FromArgb(255, 85, 85);
                        resultsBox.AppendText($"[!] {hack}\n");
                        resultsBox.SelectionColor = Color.White;
                        resultsBox.AppendText($"    Path: {path}\n\n");
                    }
                }
                else
                {
                    resultsBox.SelectionColor = Color.FromArgb(85, 255, 85);
                    resultsBox.AppendText("No Bedrock hacks detected.\n");
                }
            }
        }

        private void ShowUrlScanner()
        {
            _contentPanel.Controls.Clear();

            var title = new Label
            {
                Text = "URL SCANNER",
                ForeColor = Color.Red,
                Font = new Font("Helvetica", 16, FontStyle.Bold),
                Location = new Point(20, 20),
                AutoSize = true
            };
            _contentPanel.Controls.Add(title);

            var urlPanel = new Panel
            {
                Location = new Point(20, 60),
                Size = new Size(_contentPanel.Width - 40, 40),
                BackColor = Color.Transparent
            };
            _contentPanel.Controls.Add(urlPanel);

            var urlLabel = new Label
            {
                Text = "Enter URL:",
                ForeColor = Color.White,
                Location = new Point(0, 10),
                AutoSize = true
            };
            urlPanel.Controls.Add(urlLabel);

            var urlBox = new TextBox
            {
                Location = new Point(80, 7),
                Size = new Size(400, 30),
                Font = new Font("Helvetica", 10)
            };
            urlPanel.Controls.Add(urlBox);

            var scanButton = new Button
            {
                Text = "SCAN",
                BackColor = Color.Red,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(80, 30),
                Location = new Point(490, 7),
                Font = new Font("Helvetica", 10)
            };
            scanButton.FlatAppearance.BorderSize = 0;
            scanButton.Click += (sender, e) => PerformUrlScan();
            urlPanel.Controls.Add(scanButton);

            var resultsBox = new RichTextBox
            {
                Location = new Point(20, 120),
                Size = new Size(_contentPanel.Width - 40, _contentPanel.Height - 150),
                BackColor = Color.FromArgb(34, 34, 34),
                ForeColor = Color.White,
                Font = new Font("Consolas", 10),
                ReadOnly = true
            };
            _contentPanel.Controls.Add(resultsBox);

            void PerformUrlScan()
            {
                var url = urlBox.Text;
                if (string.IsNullOrEmpty(url))
                {
                    MessageBox.Show("Please enter a URL", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                resultsBox.Clear();
                var result = _scanner.ScanUrl(url);

                resultsBox.SelectionFont = new Font("Consolas", 10, FontStyle.Bold);
                resultsBox.AppendText($"Scan Results for: {url}\n\n");

                if (result["status"].ToString() == "clean")
                {
                    resultsBox.SelectionColor = Color.FromArgb(85, 255, 85);
                    resultsBox.AppendText("Status: CLEAN\n");
                }
                else if (result["status"].ToString() == "suspicious")
                {
                    resultsBox.SelectionColor = Color.FromArgb(255, 85, 85);
                    resultsBox.AppendText("Status: SUSPICIOUS\n");
                }
                else
                {
                    resultsBox.SelectionColor = Color.FromArgb(255, 85, 85);
                    resultsBox.AppendText("Status: ERROR\n");
                }

                if (result.ContainsKey("details"))
                {
                    resultsBox.SelectionColor = Color.White;
                    resultsBox.AppendText($"\nDetails: {result["details"]}\n");
                }

                if (result.ContainsKey("whois"))
                {
                    resultsBox.SelectionColor = Color.White;
                    resultsBox.AppendText("\nWHOIS Information:\n");
                    // Display WHOIS info - implementation depends on your WHOIS library
                }
            }
        }

        private void ShowVpnDetection()
        {
            _contentPanel.Controls.Clear();

            var title = new Label
            {
                Text = "VPN DETECTION",
                ForeColor = Color.Red,
                Font = new Font("Helvetica", 16, FontStyle.Bold),
                Location = new Point(20, 20),
                AutoSize = true
            };
            _contentPanel.Controls.Add(title);

            var ipPanel = new Panel
            {
                Location = new Point(20, 60),
                Size = new Size(_contentPanel.Width - 40, 40),
                BackColor = Color.Transparent
            };
            _contentPanel.Controls.Add(ipPanel);

            var ipLabel = new Label
            {
                Text = "Enter IP:",
                ForeColor = Color.White,
                Location = new Point(0, 10),
                AutoSize = true
            };
            ipPanel.Controls.Add(ipLabel);

            var ipBox = new TextBox
            {
                Location = new Point(60, 7),
                Size = new Size(150, 30),
                Font = new Font("Helvetica", 10)
            };
            ipPanel.Controls.Add(ipBox);

            var checkButton = new Button
            {
                Text = "CHECK",
                BackColor = Color.Red,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(80, 30),
                Location = new Point(220, 7),
                Font = new Font("Helvetica", 10)
            };
            checkButton.FlatAppearance.BorderSize = 0;
            checkButton.Click += async (sender, e) => await PerformVpnCheck();
            ipPanel.Controls.Add(checkButton);

            var resultsBox = new RichTextBox
            {
                Location = new Point(20, 120),
                Size = new Size(_contentPanel.Width - 40, _contentPanel.Height - 150),
                BackColor = Color.FromArgb(34, 34, 34),
                ForeColor = Color.White,
                Font = new Font("Consolas", 10),
                ReadOnly = true
            };
            _contentPanel.Controls.Add(resultsBox);

            async Task PerformVpnCheck()
            {
                var ip = ipBox.Text;
                if (string.IsNullOrEmpty(ip))
                {
                    MessageBox.Show("Please enter an IP address", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                resultsBox.Clear();
                var isVpn = await _scanner.CheckVpn(ip);

                if (isVpn)
                {
                    resultsBox.SelectionColor = Color.FromArgb(255, 85, 85);
                    resultsBox.AppendText($"IP {ip} is associated with VPN/proxy\n");
                }
                else
                {
                    resultsBox.SelectionColor = Color.FromArgb(85, 255, 85);
                    resultsBox.AppendText($"IP {ip} appears to be clean\n");
                }
            }
        }

        private void ShowRemoteScan()
        {
            _contentPanel.Controls.Clear();

            var title = new Label
            {
                Text = "REMOTE SYSTEM SCAN",
                ForeColor = Color.Red,
                Font = new Font("Helvetica", 16, FontStyle.Bold),
                Location = new Point(20, 20),
                AutoSize = true
            };
            _contentPanel.Controls.Add(title);

            var ipPanel = new Panel
            {
                Location = new Point(20, 60),
                Size = new Size(_contentPanel.Width - 40, 40),
                BackColor = Color.Transparent
            };
            _contentPanel.Controls.Add(ipPanel);

            var ipLabel = new Label
            {
                Text = "Target IP:",
                ForeColor = Color.White,
                Location = new Point(0, 10),
                AutoSize = true
            };
            ipPanel.Controls.Add(ipLabel);

            var ipBox = new TextBox
            {
                Location = new Point(80, 7),
                Size = new Size(150, 30),
                Font = new Font("Helvetica", 10)
            };
            ipPanel.Controls.Add(ipBox);

            var scanButton = new Button
            {
                Text = "SCAN",
                BackColor = Color.Red,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(80, 30),
                Location = new Point(240, 7),
                Font = new Font("Helvetica", 10)
            };
            scanButton.FlatAppearance.BorderSize = 0;
            scanButton.Click += async (sender, e) => await PerformRemoteScan();
            ipPanel.Controls.Add(scanButton);

            var resultsBox = new RichTextBox
            {
                Location = new Point(20, 120),
                Size = new Size(_contentPanel.Width - 40, _contentPanel.Height - 150),
                BackColor = Color.FromArgb(34, 34, 34),
                ForeColor = Color.White,
                Font = new Font("Consolas", 10),
                ReadOnly = true
            };
            _contentPanel.Controls.Add(resultsBox);

            async Task PerformRemoteScan()
            {
                var ip = ipBox.Text;
                if (string.IsNullOrEmpty(ip))
                {
                    MessageBox.Show("Please enter a target IP", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                resultsBox.Clear();
                resultsBox.AppendText($"Scanning remote system at {ip}...\n");

                var detected = await _detector.RemoteScan(ip);

                if (detected.Any())
                {
                    resultsBox.SelectionColor = Color.FromArgb(255, 85, 85);
                    resultsBox.AppendText("\n=== DETECTED HACKS ===\n\n");

                    foreach (var (hack, path) in detected)
                    {
                        resultsBox.SelectionColor = Color.FromArgb(255, 85, 85);
                        resultsBox.AppendText($"[!] {hack}\n");
                        resultsBox.SelectionColor = Color.White;
                        resultsBox.AppendText($"    Path: {path}\n\n");
                    }
                }
                else
                {
                    resultsBox.SelectionColor = Color.FromArgb(255, 255, 85);
                    resultsBox.AppendText("\nNo hacks detected or connection failed.\n");
                }
            }
        }

        private void ShowSettings()
        {
            _contentPanel.Controls.Clear();

            var title = new Label
            {
                Text = "SETTINGS",
                ForeColor = Color.Red,
                Font = new Font("Helvetica", 16, FontStyle.Bold),
                Location = new Point(20, 20),
                AutoSize = true
            };
            _contentPanel.Controls.Add(title);

            var settingsPanel = new Panel
            {
                Location = new Point(20, 60),
                Size = new Size(_contentPanel.Width - 40, _contentPanel.Height - 100),
                BackColor = Color.Transparent
            };
            _contentPanel.Controls.Add(settingsPanel);

            // Theme settings
            var themeLabel = new Label
            {
                Text = "Theme:",
                ForeColor = Color.White,
                Font = new Font("Helvetica", 12),
                Location = new Point(0, 0),
                AutoSize = true
            };
            settingsPanel.Controls.Add(themeLabel);

            var darkRadio = new RadioButton
            {
                Text = "Dark",
                ForeColor = Color.White,
                Location = new Point(0, 30),
                AutoSize = true,
                Checked = true
            };
            settingsPanel.Controls.Add(darkRadio);

            var lightRadio = new RadioButton
            {
                Text = "Light",
                ForeColor = Color.White,
                Location = new Point(0, 60),
                AutoSize = true
            };
            settingsPanel.Controls.Add(lightRadio);

            // Scan options
            var scanLabel = new Label
            {
                Text = "Scan Options:",
                ForeColor = Color.White,
                Font = new Font("Helvetica", 12),
                Location = new Point(0, 100),
                AutoSize = true
            };
            settingsPanel.Controls.Add(scanLabel);

            var deepScanCheck = new CheckBox
            {
                Text = "Enable Deep Scan",
                ForeColor = Color.White,
                Location = new Point(0, 130),
                AutoSize = true
            };
            settingsPanel.Controls.Add(deepScanCheck);

            // Save button
            var saveButton = new Button
            {
                Text = "SAVE SETTINGS",
                BackColor = Color.Red,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(150, 40),
                Location = new Point(0, 180),
                Font = new Font("Helvetica", 10)
            };
            saveButton.FlatAppearance.BorderSize = 0;
            saveButton.Click += (sender, e) => 
            {
                MessageBox.Show("Settings saved successfully!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
            settingsPanel.Controls.Add(saveButton);
        }

        private Bitmap CreatePlaceholderImage(int width, int height, string text, Color color)
        {
            var bmp = new Bitmap(width, height);
            using (var g = Graphics.FromImage(bmp))
            using (var brush = new SolidBrush(Color.FromArgb(17, 17, 17)))
            {
                g.FillRectangle(brush, 0, 0, width, height);

                // Draw gradient
                for (int i = 0; i < height; i++)
                {
                    int r = color == Color.Red ? (int)(255 * i / height) : 40;
                    using (var lineBrush = new SolidBrush(Color.FromArgb(r, 0, 0)))
                    {
                        g.FillRectangle(lineBrush, 0, i, width, 1);
                    }
                }

                // Draw text
                var font = new Font("Arial", 12, FontStyle.Bold);
                var textSize = g.MeasureString(text, font);
                var textPos = new PointF((width - textSize.Width) / 2, (height - textSize.Height) / 2);
                g.DrawString(text, font, Brushes.White, textPos);
            }

            return bmp;
        }
    }

    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            
            // URL del servidor de autenticación (debes reemplazarla con tu URL real)
            string authUrl = "https://tuservidor.com/auth";
            
            Application.Run(new ModernGUI(authUrl));
        }
    }
}