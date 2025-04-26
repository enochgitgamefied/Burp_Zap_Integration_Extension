# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab

# Java Swing imports
from javax.swing import (
    JPanel, JButton, JTextField, JLabel, JScrollPane,
    JTextArea, JComboBox, BoxLayout, SwingUtilities,
    JSplitPane, ImageIcon, JProgressBar, BorderFactory,
    JFileChooser
)
from javax.swing.border import (
    EmptyBorder, TitledBorder, LineBorder,
    CompoundBorder
)
from javax.swing.plaf.basic import BasicProgressBarUI
from javax.swing.filechooser import FileNameExtensionFilter

# Java AWT imports
from java.awt import (
    Dimension, GridLayout, Color, Font,
    BorderLayout, GradientPaint, Polygon,
    FlowLayout
)

# Java IO imports
from java.io import (
    ByteArrayInputStream,
    BufferedReader, InputStreamReader
)
from javax.imageio import ImageIO
from java.lang import ProcessBuilder

# Python imports
import threading
import time
import re
import urllib2
import json
import socket
from urllib import quote as url_quote
import os
import subprocess


class NeedleProgressUI(BasicProgressBarUI):
    def paintDeterminate(self, g, c):
        progressBar = c
        insets = progressBar.getInsets()
        width = progressBar.getWidth() - (insets.left + insets.right)
        height = progressBar.getHeight() - (insets.top + insets.bottom)
        
        progress = progressBar.getValue()
        barWidth = int(width * (progress / 100.0))
        barHeight = height
        
        # Draw background
        g.color = Color(240, 240, 240)
        g.fillRect(insets.left, insets.top, width, height)
        
        # Draw gradient progress
        gradient = GradientPaint(
            0, 0, Color(100, 150, 255), 
            width, 0, Color(50, 100, 200))
        g.setPaint(gradient)
        g.fillRect(insets.left, insets.top, barWidth, barHeight)
        
        # Draw needle
        needle_x = insets.left + barWidth
        needle = Polygon(
            [needle_x, needle_x-10, needle_x+10],
            [insets.top, insets.top+20, insets.top+20], 3)
        g.color = Color.RED
        g.fillPolygon(needle)
        
        # Draw border
        g.color = Color.GRAY
        g.drawRect(insets.left, insets.top, width, height)
        
        # Draw text
        if progressBar.isStringPainted():
            self.paintString(g, insets.left, insets.top,
                           width, height,
                           barWidth, insets)

    def getAmountFull(self, insets, width, height):
        return 0


class ProgressNeedle(JPanel):
    def __init__(self):
        self.setLayout(BorderLayout())
        self.setBorder(BorderFactory.createCompoundBorder(
            TitledBorder("Scan Progress"),
            EmptyBorder(10, 10, 10, 10)
        ))
        self.setMaximumSize(Dimension(800, 60))
        
        self.progress_bar = JProgressBar(0, 100)
        self.progress_bar.setStringPainted(True)
        self.progress_bar.setFont(Font("Arial", Font.BOLD, 12))
        self.progress_bar.setForeground(Color(70, 130, 180))
        self.progress_bar.setUI(NeedleProgressUI())
        
        self._completed = False
        self._last_value = 0
        
        self.add(self.progress_bar, BorderLayout.CENTER)
    
    def update_progress(self, value):
        def update():
            if not self._completed or value < self._last_value:
                self.progress_bar.setValue(value)
                self.progress_bar.setString("{}%".format(value))
                self._last_value = value
                if value == 100:
                    self._completed = True
                elif value < 100:
                    self._completed = False
                self.progress_bar.repaint()
        SwingUtilities.invokeLater(update)
    
    def reset_progress(self):
        def _reset():
            self._completed = False
            self._last_value = 0
            self.progress_bar.setValue(0)
            self.progress_bar.setString("0%")
            self.progress_bar.repaint()
        SwingUtilities.invokeLater(_reset)
    
    def is_complete(self):
        return self._completed
    
    def get_current_progress(self):
        return self._last_value


class BurpExtender(IBurpExtender, ITab):
    def __init__(self):
        self.callbacks = None
        self.helpers = None
        self._ui_initialized = False
        self.lock = threading.Lock()
        self.scan_active = False
        self.hardcoded_api_key = None
        self.hardcoded_port = None
        self.output_area = None
        self.current_scan_id = None
        self.should_stop = False

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ZAP DAST")
        
        # Initialize output area before UI
        self.output_area = JTextArea(15, 60)
        self.output_area.setEditable(False)
        self.output_area.setFont(Font("Monospaced", Font.PLAIN, 12))
               
        self._initialize_ui()
        self._ui_initialized = True
        callbacks.addSuiteTab(self)
        self.progress_panel.reset_progress()
        
        # Load saved configuration
        self.api_key_input.setText(self._get_config_setting("zap_api_key", ""))
        self.port_input.setText(self._get_config_setting("zap_port", "8082"))
        

    def log(self, message):
        """Thread-safe logging method"""
        if not hasattr(self, 'output_area') or not self.output_area:
            print "[PRE-UI] {}".format(message)
            return
            
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        def _log():
            try:
                self.output_area.append("[{}] {}\n".format(timestamp, message))
                self.output_area.setCaretPosition(self.output_area.getDocument().getLength())
            except Exception as e:
                print "Logging failed: {}".format(str(e))
        SwingUtilities.invokeLater(_log)

    def _initialize_ui(self):
        try:
            # Main panel with vertical box layout
            self.panel = JPanel()
            self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
            
            # Create split pane
            self.split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            self.split_pane.setResizeWeight(0.25)
            self.split_pane.setDividerSize(5)

            # Top panel (logo/title)
            self.top_panel = JPanel()
            self.top_panel.setLayout(BoxLayout(self.top_panel, BoxLayout.Y_AXIS))
            self.top_panel.setMaximumSize(Dimension(800, 150))
            
            # Create centered container panel for image/title
            center_container = JPanel()
            center_container.setLayout(FlowLayout(FlowLayout.CENTER))
            center_container.setBorder(EmptyBorder(10, 0, 10, 0))
            
            self._show_text_title()

            self.top_panel.add(center_container)

            # Bottom panel (controls)
            self.bottom_panel = JPanel()
            self.bottom_panel.setLayout(BoxLayout(self.bottom_panel, BoxLayout.Y_AXIS))
            self.bottom_panel.setBorder(EmptyBorder(10, 10, 10, 10))

            # Configuration Panel
            config_panel = JPanel(GridLayout(0, 2, 5, 5))
            config_panel.setMaximumSize(Dimension(800, 150))
            config_panel.setBorder(TitledBorder("Configuration"))

            # ZAP JAR Path Field
            self.zap_jar_label = JLabel("ZAP JAR Path:")
            self.zap_jar_input = JTextField(25)
            self.zap_jar_input.setText(self._get_config_setting("zap_jar_path", ""))
            
            self.zap_jar_button = JButton("Browse...", actionPerformed=self._browse_zap_jar)
            zap_jar_panel = JPanel(BorderLayout())
            zap_jar_panel.add(self.zap_jar_input, BorderLayout.CENTER)
            zap_jar_panel.add(self.zap_jar_button, BorderLayout.EAST)
            
            config_panel.add(self.zap_jar_label)
            config_panel.add(zap_jar_panel)

            # API Key Field
            self.api_key_label = JLabel("ZAP API Key:")
            self.api_key_input = JTextField(25)
            config_panel.add(self.api_key_label)
            config_panel.add(self.api_key_input)

            # Port Field
            self.port_label = JLabel("ZAP Port:")
            self.port_input = JTextField("8082", 5)
            config_panel.add(self.port_label)
            config_panel.add(self.port_input)

            # Target URL Field
            self.url_label = JLabel("Target URL:")
            self.url_input = JTextField(30)
            config_panel.add(self.url_label)
            config_panel.add(self.url_input)

            # Scan Policy Dropdown
            self.policy_label = JLabel("Scan Policy:")
            self.policy_combo = JComboBox()
            config_panel.add(self.policy_label)
            config_panel.add(self.policy_combo)

            self.bottom_panel.add(config_panel)

            # Button Panel
            button_panel = JPanel()
            button_panel.setBorder(EmptyBorder(5, 0, 5, 0))
            
            self.scan_button = JButton("Start Scan", actionPerformed=self.start_scan)
            self.scan_button.setToolTipText("Start ZAP scan with current configuration")
            button_panel.add(self.scan_button)
            
            self.stop_button = JButton("Stop Scan", actionPerformed=self.stop_scan)
            self.stop_button.setEnabled(False)
            self.stop_button.setToolTipText("Stop current scan")
            button_panel.add(self.stop_button)
            
            self.load_policies_button = JButton("Load Policies", actionPerformed=self.load_policies)
            self.load_policies_button.setToolTipText("Load available scan policies from ZAP")
            button_panel.add(self.load_policies_button)
            
            self.update_config_button = JButton("Save Config", actionPerformed=self.update_config)
            self.update_config_button.setToolTipText("Save current configuration")
            button_panel.add(self.update_config_button)
            
            self.bottom_panel.add(button_panel)

            # ZAP Launcher Buttons
            launcher_panel = JPanel()
            self.zap_launcher_button = JButton("Launch ZAP", actionPerformed=self.launch_zap)
            self.zap_launcher_button.setFont(Font("Arial", Font.BOLD, 12))
            self.zap_launcher_button.setBackground(Color(70, 130, 180))
            self.zap_launcher_button.setForeground(Color.WHITE)
            launcher_panel.add(self.zap_launcher_button)
            
            self.zap_closer_button = JButton("Close ZAP", actionPerformed=self.close_zap)
            self.zap_closer_button.setFont(Font("Arial", Font.BOLD, 12))
            self.zap_closer_button.setBackground(Color(200, 50, 50))  # Red color
            self.zap_closer_button.setForeground(Color.WHITE)
            self.zap_closer_button.setEnabled(True)
            launcher_panel.add(self.zap_closer_button)
            
            self.bottom_panel.add(launcher_panel)

            # Progress Needle Panel
            self.progress_panel = ProgressNeedle()
            self.bottom_panel.add(self.progress_panel)

            # Output Log Area
            output_panel = JPanel()
            output_panel.setLayout(BoxLayout(output_panel, BoxLayout.Y_AXIS))
            scroll_pane = JScrollPane(self.output_area)
            scroll_pane.setBorder(TitledBorder("Scan Log"))
            output_panel.add(scroll_pane)
            self.bottom_panel.add(output_panel)

            # Assemble final UI
            self.split_pane.setTopComponent(self.top_panel)
            self.split_pane.setBottomComponent(self.bottom_panel)
            self.panel.add(self.split_pane)

            self.log("[+] UI initialized successfully")
            
        except Exception as e:
            error_msg = "UI initialization failed: {}".format(str(e))
            print error_msg
            if hasattr(self, 'log'):
                self.log("[CRITICAL] {}".format(error_msg))
            raise

    def _browse_zap_jar(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Select ZAP JAR File")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setAcceptAllFileFilterUsed(False)
        chooser.addChoosableFileFilter(FileNameExtensionFilter("JAR Files", ["jar"]))
        
        if chooser.showOpenDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            selected_file = chooser.getSelectedFile()
            self.zap_jar_input.setText(selected_file.getAbsolutePath())
            self._save_config_setting("zap_jar_path", selected_file.getAbsolutePath())
            self.log("[+] Saved ZAP JAR path: {}".format(selected_file.getAbsolutePath()))

    def _show_text_title(self):
        for component in self.top_panel.getComponents():
            if isinstance(component, JPanel) and component.getComponentCount() > 0:
                if isinstance(component.getComponent(0), JLabel):
                    self.top_panel.remove(component)
        
        title_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        title_label = JLabel("ZAP DAST")
        title_label.setFont(Font("Arial", Font.BOLD, 16))
        title_label.setForeground(Color(70, 130, 180))
        title_panel.add(title_label)
        self.top_panel.add(title_panel, 0)
        self.top_panel.revalidate()
        self.top_panel.repaint()

    def _get_config_setting(self, key, default):
        try:
            return self.callbacks.loadExtensionSetting(key) or default
        except:
            return default

    def _save_config_setting(self, key, value):
        try:
            self.callbacks.saveExtensionSetting(key, value)
        except Exception as e:
            self.log("[!] Error saving setting: {}".format(str(e)))

    def getTabCaption(self):
        return "ZAP DAST"

    def getUiComponent(self):
        return self.panel

    def update_config(self, event):
        self.progress_panel.reset_progress()
        api_key = self.api_key_input.getText().strip()
        port = self.port_input.getText().strip()
        
        if not api_key or not port:
            self.log("[!] Both API key and port must be provided")
            return

        # Save to internal variables
        self.hardcoded_api_key = api_key
        self.hardcoded_port = port

        # Update input fields
        self.api_key_input.setText(api_key)
        self.port_input.setText(port)

        # Save to config
        self._save_config_setting("zap_api_key", api_key)
        self._save_config_setting("zap_port", port)

        self.log("[+] Configuration updated and saved successfully")
        

    def _check_zap_running(self, port):
        """Check if ZAP is running on the specified port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', int(port)))
            sock.close()
            return result == 0
        except:
            return False

    

    def launch_zap(self, event):
        self.progress_panel.reset_progress()
        def run():
            try:
                self.log("[*] Starting ZAP...")
                
                api_key = self.hardcoded_api_key or self.api_key_input.getText().strip()
                port = self.hardcoded_port or self.port_input.getText().strip() or "8082"
                zap_jar = self.zap_jar_input.getText().strip()
                
                if not zap_jar:
                    self.log("[!] Error: ZAP JAR path not specified")
                    return
                
                if not os.path.exists(zap_jar):
                    self.log("[!] Error: ZAP jar not found at {}".format(zap_jar))
                    return
                
                cmd = [
                    "java",
                    "-jar", zap_jar,
                    "-daemon",
                    "-port", port,
                    "-config", "api.key={}".format(api_key),
                    "-nostdout"
                ]
                
                self.log("[*] Launch command: {}".format(" ".join(cmd)))
                pb = ProcessBuilder(cmd)
                pb.redirectErrorStream(True)
                process = pb.start()
                
                # Wait for ZAP to start
                time.sleep(5)
                
                
                reader = BufferedReader(InputStreamReader(process.getInputStream()))
                while True:
                    line = reader.readLine()
                    if line is None:
                        break
                    self.log("[ZAP] {}".format(line))
                
                self.log("[+] ZAP started successfully")
                
            except Exception as e:
                self.log("[!] Error launching ZAP: {}".format(str(e)))
            

        threading.Thread(target=run).start()

    def close_zap(self, event):
        """Try to shutdown ZAP gracefully or force kill it"""
        self.progress_panel.reset_progress()
        thread = threading.Thread(target=self._shutdown_zap)
        thread.setDaemon(True)  # <-- use setDaemon() method
        thread.start()


    def _shutdown_zap(self):
        """Attempt API shutdown if port is known, else kill process"""
        zap_port = self.hardcoded_port or self.port_input.getText().strip()
        zap_api_key = self.hardcoded_api_key or self.api_key_input.getText().strip()

        if zap_port:
            try:
                self.log("[*] Attempting API shutdown via port {}".format(zap_port))
                shutdown_url = "http://127.0.0.1:{}/JSON/core/action/shutdown/?apikey={}".format(
                    zap_port, zap_api_key)
                response = self._http_request(shutdown_url)

                if response.get('error'):
                    self.log("[!] API shutdown failed: {}".format(response.get('error')))
                    self._kill_zap_process()
                else:
                    self.log("[+] ZAP shutdown initiated successfully via API")
                    return
            except Exception as e:
                self.log("[!] Exception during API shutdown: {}".format(str(e)))
                # fall through to kill
        else:
            self.log("[*] No port specified — skipping API shutdown.")

        # Fallback: kill process
        self._kill_zap_process()



    def _kill_zap_process(self):
        """Attempt to terminate only the ZAP process, not all Java processes"""
        try:
            import psutil
            zap_keywords = ['zap', 'owasp-zap']
            found = False

            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info.get('cmdline') or [])
                    if any(keyword in cmdline.lower() for keyword in zap_keywords):
                        proc.kill()
                        self.log("[+] Terminated ZAP process (PID {})".format(proc.pid))
                        found = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if not found:
                self.log("[*] No ZAP process found running.")
        except Exception as e:
            self.log("[!] Failed to kill ZAP process: {}".format(str(e)))


    def load_policies(self, event):
        self.progress_panel.reset_progress()
        try:
            zap_api_key = self.hardcoded_api_key or self.api_key_input.getText().strip()
            zap_port = self.hardcoded_port or self.port_input.getText().strip()
            
            if not zap_port:
                raise ValueError("ZAP Port is required")
            
            self.log("[*] Loading scan policies from ZAP...")
            policies = self._get_scan_policies(zap_port, zap_api_key)
            
            if not policies:
                raise Exception("No scan policies found")
                
            self.policy_combo.removeAllItems()
            for policy in policies:
                self.policy_combo.addItem(policy)
                
            self.log("[+] Loaded {} scan policies".format(len(policies)))
            
        except Exception as e:
            self.log("[!] Error loading policies: {}".format(str(e)))

    def start_scan(self, event):
        self.progress_panel.reset_progress() 
        if self.scan_active:
            self.log("[!] Scan already in progress")
            return
            
        SwingUtilities.invokeLater(lambda: [
            self.scan_button.setEnabled(False),
            self.stop_button.setEnabled(True)
        ])
        
        threading.Thread(target=self._run_scan).start()

    def _run_scan(self):
        try:
            with self.lock:
                self.scan_active = True
                self.should_stop = False
                
                # Get scan parameters
                zap_api_key = self.hardcoded_api_key or self.api_key_input.getText().strip()
                zap_port = self.hardcoded_port or self.port_input.getText().strip()
                target_url = self.url_input.getText().strip()
                
                # Validate inputs
                if not zap_port or not zap_port.isdigit():
                    raise ValueError("Invalid port number")
                if not target_url or not re.match(r'^https?://', target_url, re.I):
                    raise ValueError("Invalid URL format")
                if self.policy_combo.getItemCount() == 0:
                    raise Exception("No scan policies loaded")
                    
                scan_policy = str(self.policy_combo.getSelectedItem())
                
                # Reset progress bar
                self.progress_panel.update_progress(0)
                
                # Context creation
                context_id = self._create_context(zap_port, zap_api_key, target_url)
                if not context_id:
                    raise Exception("Failed to create context")
                
                # Spider phase (0-50% progress)
                spider_id = self._start_spider(zap_port, zap_api_key, target_url, context_id)
                if not spider_id:
                    raise Exception("Failed to start spider")
                
                if not self._wait_for_spider(zap_port, zap_api_key, spider_id):
                    raise Exception("Spider timed out")
                
                if self.should_stop:
                    self.log("[*] Scan stopped by user after spider phase")
                    return
                
                # Active scan phase (50-100% progress)
                scan_url = "http://127.0.0.1:{}/JSON/ascan/action/scan?apikey={}&url={}&contextId={}&scanPolicyName={}".format(
                    zap_port,
                    zap_api_key,
                    url_quote(target_url),
                    context_id,
                    url_quote(scan_policy))
                
                scan_response = self._http_request(scan_url)
                if scan_response.get('error'):
                    raise Exception("Scan error: " + str(scan_response.get('error')))
                
                self.current_scan_id = str(scan_response['body'].get('scan'))
                if not self.current_scan_id:
                    raise Exception("No scan ID returned")
                
                self.log("[+] Scan started. ID: " + self.current_scan_id)
                
                # Track scan progress
                if not self._wait_for_scan(zap_port, zap_api_key, self.current_scan_id):
                    self.log("[!] Scan did not complete successfully")
                
                self.log("[+] Scan completed successfully")
                
        except Exception as e:
            self.log("[!] Scan error: " + str(e))
            error_msg = str(e)
            if "Connection refused" in error_msg:
                self.log("[!] Is ZAP running and accessible?")
            elif "timed out" in error_msg:
                self.log("[!] Operation timed out - check network connectivity")
        
        finally:
            self.scan_complete()

    def _create_context(self, port, api_key, target_url):
        """Create a new context in ZAP for the scan"""
        try:
            context_name = "BurpScan_" + str(int(time.time()))
            self.log("[*] Creating scan context: " + context_name)
            
            # Create new context
            context_url = "http://127.0.0.1:%s/JSON/context/action/newContext?apikey=%s&contextName=%s" % (
                port, api_key, context_name)
            response = self._http_request(context_url)
            
            if response.get('error'):
                if "ALREADY_EXISTS" in str(response.get('error')):
                    self.log("[*] Context exists, reusing...")
                    context_id = self._get_context_id(port, api_key, context_name)
                    if context_id:
                        self._clean_context(port, api_key, context_name)
                        return context_id
                return None
            
            context_id = response['body'].get('contextId')
            if not context_id:
                return None
            
            # Include target URL in context
            include_url = "http://127.0.0.1:%s/JSON/context/action/includeInContext?apikey=%s&contextName=%s&regex=%s" % (
                port, api_key, context_name, url_quote("^%s.*" % re.escape(target_url)))
            self._http_request(include_url)
            
            self.log("[+] Context created: " + context_id)
            return context_id
            
        except Exception as e:
            self.log("[!] Context creation error: " + str(e))
            return None

    def _get_scan_policies(self, port, api_key):
        url = "http://127.0.0.1:%s/JSON/ascan/view/scanPolicyNames?apikey=%s" % (port, api_key)
        response = self._http_request(url)
        if response.get('error') or response['status'] != 200:
            self.log("[!] Failed to get scan policies: %s" % response.get('error', 'Unknown error'))
            return None
        return response['body'].get('scanPolicyNames', [])

    def _get_context_id(self, port, api_key, context_name):
        url = "http://127.0.0.1:%s/JSON/context/view/context?apikey=%s&contextName=%s" % (
            port, api_key, context_name)
        response = self._http_request(url)
        if response.get('error') or response['status'] != 200:
            raise Exception("Failed to get context ID: %s" % response.get('error', 'Unknown error'))
        return response['body'].get('context', {}).get('id')

    def _clean_context(self, port, api_key, context_name):
        self.log("[*] Cleaning existing context...")
        urls = [
            ("excludeAllContextTechnologies", "technologies"),
            ("excludeAllContextUrls", "URLs"),
            ("includeAllContextTechnologies", "technologies"),
            ("includeAllContextUrls", "URLs")
        ]
        
        for action, desc in urls:
            url = "http://127.0.0.1:%s/JSON/context/action/%s?apikey=%s&contextName=%s" % (
                port, action, api_key, context_name)
            response = self._http_request(url)
            if response.get('error'):
                self.log("[!] Warning: Failed to clear context %s: %s" % (desc, response.get('error')))
        
        self.log("[+] Context cleaned successfully")

    def _start_spider(self, port, api_key, target_url, context_id):
        spider_url = "http://127.0.0.1:%s/JSON/spider/action/scan?apikey=%s&url=%s&contextId=%s" % (
            port, api_key, url_quote(target_url), context_id)
        response = self._http_request(spider_url)
        if response.get('error') or response['status'] != 200:
            self.log("[!] Failed to start spider: %s" % response.get('error', 'Unknown error'))
            return None
        
        spider_id = response['body'].get('scan')
        if not spider_id:
            self.log("[!] No spider ID returned")
            return None
            
        self.log("[+] Spider started with ID: %s" % spider_id)
        return spider_id

    def _wait_for_spider(self, port, api_key, spider_id, timeout=300):
        self.log("[*] Waiting for spider to complete (0-50% progress)...")
        start = time.time()
        
        while time.time() - start < timeout:
            if self.should_stop:
                self.log("[*] Stopping spider per user request")
                return False
                
            status_url = "http://127.0.0.1:%s/JSON/spider/view/status?apikey=%s&scanId=%s" % (
                port, api_key, spider_id)
            response = self._http_request(status_url)
            
            if response.get('error'):
                self.log("[!] Error checking spider status: %s" % response.get('error', 'Unknown error'))
                return False
            
            status = int(response['body'].get('status', 0))
            # Map spider progress to 0-50% range
            self.progress_panel.update_progress(status // 2)
            
            if status >= 100:
                self.log("[+] Spider completed (50%)")
                return True
                
            time.sleep(2)
        
        self.log("[!] Spider timed out")
        return False

    def _wait_for_scan(self, port, api_key, scan_id, timeout=1800):
        self.log("[*] Waiting for scan to complete (50-100% progress)...")
        start = time.time()
        
        while time.time() - start < timeout:
            if self.should_stop:
                self.log("[*] Stopping scan per user request")
                return False
                
            status_url = "http://127.0.0.1:%s/JSON/ascan/view/status?apikey=%s&scanId=%s" % (
                port, api_key, scan_id)
            response = self._http_request(status_url)
            
            if response.get('error'):
                self.log("[!] Error checking scan status: %s" % response.get('error', 'Unknown error'))
                return False
            
            status = int(response['body'].get('status', 0))
            # Map scan progress to 50-100% range
            self.progress_panel.update_progress(50 + (status // 2))
            
            if status >= 100:
                self.log("[+] Scan completed (100%)")
                return True
                
            time.sleep(5)
        
        self.log("[!] Scan timed out")
        return False

    def _http_request(self, url, params=None):
        """Enhanced HTTP request with params handling for Jython"""
        try:
            if params:
                query_parts = []
                for k, v in params.items():
                    query_parts.append("%s=%s" % (k, url_quote(str(v))))
                url += "?" + "&".join(query_parts)
            
            req = urllib2.Request(url)
            response = urllib2.urlopen(req, timeout=10)
            response_body = response.read()
            
            try:
                json_data = json.loads(response_body)
                return {
                    'status': response.getcode(),
                    'body': json_data
                }
            except ValueError as e:
                return {'error': "JSON parse error: %s" % str(e)}
                
        except urllib2.URLError as e:
            if isinstance(e.reason, socket.timeout):
                return {'error': "Connection timeout after 10 seconds"}
            elif isinstance(e.reason, socket.error):
                return {'error': "Connection refused - is ZAP running?"}
            return {'error': "URL Error: %s" % str(e)}
        except Exception as e:
            return {'error': "Unexpected error: %s" % str(e)}

    def scan_complete(self):
        with self.lock:
            self.scan_active = False
            self.current_scan_id = None
            self.should_stop = False
            SwingUtilities.invokeLater(lambda: [
                self.scan_button.setEnabled(True),
                self.stop_button.setEnabled(False),
            ])
        self.log("[*] Scan process completed")

    def stop_all_scans(self):
        """Stop all active ZAP scans"""
        try:
            zap_port = self.hardcoded_port or self.port_input.getText().strip()
            zap_api_key = self.hardcoded_api_key or self.api_key_input.getText().strip()
            
            stop_url = "http://127.0.0.1:%s/JSON/ascan/action/stopAllScans" % zap_port
            params = {
                "apikey": zap_api_key
            }
            
            response = self._http_request(stop_url, params)
            
            if response.get('error'):
                raise Exception(response['error'])
            
            self.log("[+] All scans stopped successfully")
            return True
            
        except Exception as e:
            self.log("[!] Error stopping scans: %s" % str(e))
            return False

    def stop_scan(self, event):
        self.log("[*] Attempting to stop scan...")
        try:
            with self.lock:
                if not self.scan_active:
                    self.log("[!] No scan is active")
                    return

                self.should_stop = True
                
                zap_api_key = self.hardcoded_api_key or self.api_key_input.getText().strip()
                zap_port = self.hardcoded_port or self.port_input.getText().strip()
                
                if self.current_scan_id:
                    stop_url = "http://127.0.0.1:%s/JSON/ascan/action/stopScan?apikey=%s&scanId=%s" % (
                        zap_port, zap_api_key, self.current_scan_id)
                    
                    response = self._http_request(stop_url)
                    
                    if response.get('error'):
                        raise Exception("Stop scan error: %s" % response['error'])
                    if response['status'] != 200:
                        raise Exception("Failed to stop scan - Status %s" % response['status'])
                
                self.log("[+] Scan stopped successfully!")
                self.scan_complete()
            
        except Exception as e:
            self.log("[!] Error during scan stop: %s" % str(e))
            self.scan_complete()