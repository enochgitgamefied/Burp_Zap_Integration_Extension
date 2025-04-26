# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab
from javax.swing import (
    JPanel, JButton, JTabbedPane, JScrollPane, JTable,
    BoxLayout, JSplitPane, BorderFactory, JLabel, JComboBox, JTextField,
    JFileChooser, JTextArea, SwingWorker, JOptionPane, JToggleButton
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import Color, Font, Dimension, EventQueue, GridBagLayout, GridBagConstraints, Insets, BorderLayout
from java.lang import Object, Runnable, Thread
import json
import urllib2
from urllib import quote as url_quote
from javax.swing import Box
from javax.swing.filechooser import FileNameExtensionFilter
import os
import time
from java.io import File, FileWriter, FileOutputStream
import tempfile
import subprocess
import base64
from javax.swing import JPanel, JToggleButton, BorderFactory, Box, BoxLayout
from java.awt import BorderLayout, Color, Font
from javax.swing.plaf.metal import MetalIconFactory

from javax.swing import (
    JPanel, JToggleButton, BoxLayout, Box, BorderFactory
)
from java.awt import BorderLayout, Color, Font, event
from javax.swing.tree import DefaultTreeCellRenderer
from javax.swing.plaf.basic import BasicToggleButtonUI

class CollapsiblePanel(JPanel):
    def __init__(self, title, content_panel):
        super(CollapsiblePanel, self).__init__()
        self.setLayout(BorderLayout())
        self.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0))

        # Use a standard renderer to grab triangle icons
        renderer = DefaultTreeCellRenderer()
        self.right_arrow = renderer.getClosedIcon()
        self.down_arrow = renderer.getOpenIcon()

        # Panel to toggle
        self.content_panel = content_panel
        self.content_panel.setVisible(False)

        # Header toggle
        self._init_header(title)

        # Add to main layout
        self.add(self.header_panel, BorderLayout.NORTH)
        self.add(self.content_panel, BorderLayout.CENTER)

    def _init_header(self, title):
        self.header_panel = JPanel()
        self.header_panel.setLayout(BoxLayout(self.header_panel, BoxLayout.X_AXIS))
        self.header_panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, Color.GRAY),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ))

        self.toggle_button = JToggleButton(title)
        self.toggle_button.setSelected(False)
        self.toggle_button.setFont(Font("Dialog", Font.BOLD, 12))
        self.toggle_button.setForeground(Color.BLACK)
        self.toggle_button.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2))
        self.toggle_button.setContentAreaFilled(False)
        self.toggle_button.setFocusable(False)
        self.toggle_button.setIcon(self.right_arrow)
        self.toggle_button.setIconTextGap(8)
        
        # This ensures the color doesn't change when selected
        self.toggle_button.setOpaque(False)
        self.toggle_button.setUI(BasicToggleButtonUI())  # Use basic UI to avoid LAF changes
        
        self.toggle_button.addActionListener(self._toggle_action)
        self.header_panel.add(self.toggle_button)
        self.header_panel.add(Box.createHorizontalGlue())

    def _toggle_action(self, event):
        is_selected = self.toggle_button.isSelected()
        self.toggle_button.setIcon(self.down_arrow if is_selected else self.right_arrow)
        self.toggle_button.setForeground(Color.BLACK)  # Force black text color
        self.content_panel.setVisible(is_selected)
        self.revalidate()
        self.repaint()


class BurpExtender(IBurpExtender, ITab):
    def __init__(self):
        self.current_page = 1
        self.page_size = 50
        self.current_risk_level = None
        self.current_alerts = []
        
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ZAP Report Generator")
        self._init_ui()
        callbacks.addSuiteTab(self)
        
    def _init_ui(self):
        # Main panel with proper spacing
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
        self.panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # Create collapsible configuration panels
        self._create_config_panel()
        self._create_options_panel()
        
        # Control Buttons (always visible)
        btn_panel = JPanel()
        btn_panel.setLayout(BoxLayout(btn_panel, BoxLayout.X_AXIS))
        btn_panel.setAlignmentX(JPanel.LEFT_ALIGNMENT)
        
        self.report_btn = JButton("Generate Report", actionPerformed=self.generate_report)
        btn_panel.add(self.report_btn)
        
        self.export_btn = JButton("Export Report", actionPerformed=self.export_report)
        self.export_btn.setEnabled(False)
        btn_panel.add(Box.createHorizontalStrut(10))
        btn_panel.add(self.export_btn)
        
        btn_container = JPanel()
        btn_container.setLayout(BoxLayout(btn_container, BoxLayout.X_AXIS))
        btn_container.add(Box.createHorizontalGlue())
        btn_container.add(btn_panel)
        btn_container.add(Box.createHorizontalGlue())
        
        self.panel.add(btn_container)
        self.panel.add(Box.createVerticalStrut(10))
        
        # Status Panel (always visible)
        status_panel = JPanel()
        status_panel.setLayout(BoxLayout(status_panel, BoxLayout.Y_AXIS))
        status_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        self.output_area = JTextArea(4, 80)
        self.output_area.setEditable(False)
        self.output_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        scroll_pane = JScrollPane(self.output_area)
        scroll_pane.setBorder(BorderFactory.createTitledBorder("Status"))
        status_panel.add(scroll_pane)
        
        self.panel.add(status_panel)
        self.panel.add(Box.createVerticalStrut(10))
        
        # Results Panel (always visible)
        results_panel = JPanel()
        results_panel.setLayout(BoxLayout(results_panel, BoxLayout.Y_AXIS))
        results_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        self.results_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.results_split.setResizeWeight(0.7)
        self.results_split.setDividerSize(5)
        self.results_split.setBorder(BorderFactory.createEmptyBorder())
        
        self.report_tabs_panel = JPanel()
        self.report_tabs_panel.setLayout(BoxLayout(self.report_tabs_panel, BoxLayout.Y_AXIS))
        self.report_tabs_panel.setBorder(BorderFactory.createEmptyBorder())
        
        self.details_tabs = JTabbedPane()
        self.details_tabs.setPreferredSize(Dimension(10000, 250))
        
        self._init_empty_details_tab()
        
        self.results_split.setTopComponent(self.report_tabs_panel)
        self.results_split.setBottomComponent(self.details_tabs)
        results_panel.add(self.results_split)
        
        self.panel.add(results_panel)

    def _create_config_panel(self):
        """Create the ZAP Configuration panel as a collapsible panel"""
        config_panel = JPanel()
        config_panel.setLayout(GridBagLayout())
        config_panel.setMaximumSize(Dimension(600, 150))
        
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        # Load saved values
        
        self.saved_config = {
            'zap_api_key': self._load_setting('zap_api_key', ''),  # Empty default
            'zap_port': self._load_setting('zap_port', '8082')
        }
        
        # API Key
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.weightx = 0.0
        config_panel.add(JLabel("API Key:"), gbc)
        gbc.gridx = 1
        gbc.weightx = 1.0
        self.api_key_field = JTextField(self.saved_config['zap_api_key'], 20)
        config_panel.add(self.api_key_field, gbc)
        
        # Port
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.weightx = 0.0
        config_panel.add(JLabel("Port:"), gbc)
        gbc.gridx = 1
        gbc.weightx = 1.0
        self.port_field = JTextField(self.saved_config['zap_port'], 10)
        config_panel.add(self.port_field, gbc)
        
        # Save Button
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.gridwidth = 3
        gbc.weightx = 1.0
        save_btn = JButton("Save Configuration", actionPerformed=self._save_config)
        config_panel.add(save_btn, gbc)
        
        # Create collapsible panel
        self.config_collapsible = CollapsiblePanel("ZAP Configuration", config_panel)
        self.panel.add(self.config_collapsible)

    def _create_options_panel(self):
        """Create the Report Options panel as a collapsible panel"""
        options_panel = JPanel()
        options_panel.setLayout(GridBagLayout())
        options_panel.setMaximumSize(Dimension(600, 150))
        
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        # Report Title
        gbc.gridx = 0
        gbc.gridy = 0
        options_panel.add(JLabel("Report Title:"), gbc)
        gbc.gridx = 1
        gbc.weightx = 1.0
        self.title_field = JTextField("Burp-ZAP Security Report", 20)
        options_panel.add(self.title_field, gbc)
        
        # Template Selection
        gbc.gridx = 0
        gbc.gridy = 1
        options_panel.add(JLabel("Template:"), gbc)
        gbc.gridx = 1
        self.template_combo = JComboBox(["traditional-html", "traditional-html-plus","modern", "traditional-md", "traditional-pdf", "traditional-xml"])
        options_panel.add(self.template_combo, gbc)
        
        # Create collapsible panel
        self.options_collapsible = CollapsiblePanel("Report Options", options_panel)
        self.panel.add(self.options_collapsible)

    def _init_empty_details_tab(self):
        self.details_tabs.removeAll()
        
        req_panel = JPanel()
        req_panel.setLayout(BoxLayout(req_panel, BoxLayout.Y_AXIS))
        self.req_text = JTextArea()
        self.req_text.setEditable(False)
        self.req_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        req_panel.add(JScrollPane(self.req_text))
        
        resp_panel = JPanel()
        resp_panel.setLayout(BoxLayout(resp_panel, BoxLayout.Y_AXIS))
        self.resp_text = JTextArea()
        self.resp_text.setEditable(False)
        self.resp_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        resp_panel.add(JScrollPane(self.resp_text))
        
        self.details_tabs.addTab("Request", req_panel)
        self.details_tabs.addTab("Response", resp_panel)

    def export_report(self, event):
        """Export the report using ZAP's built-in report generation endpoint"""
        if not hasattr(self, 'current_alerts') or not self.current_alerts:
            self._log("No report data to export")
            return
            
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Report As")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        
        # Determine file extension based on template
        template = str(self.template_combo.getSelectedItem())
        if "pdf" in template:
            chooser.addChoosableFileFilter(FileNameExtensionFilter("PDF Files", ["pdf"]))
            default_ext = ".pdf"
        elif "xml" in template:
            chooser.addChoosableFileFilter(FileNameExtensionFilter("XML Files", ["xml"]))
            default_ext = ".xml"
        elif "md" in template:
            chooser.addChoosableFileFilter(FileNameExtensionFilter("Markdown Files", ["md"]))
            default_ext = ".md"
        else:  # Default to HTML
            chooser.addChoosableFileFilter(FileNameExtensionFilter("HTML Files", ["html"]))
            default_ext = ".html"
            
        chooser.setAcceptAllFileFilterUsed(False)
        
        default_filename = "zap_report_%s%s" % (time.strftime("%Y%m%d_%H%M%S"), default_ext)
        chooser.setSelectedFile(File(default_filename))
        
        if chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            output_file = chooser.getSelectedFile()
            
            # Ensure correct extension
            if not output_file.getName().lower().endswith(default_ext):
                output_file = File(output_file.getParentFile(), output_file.getName() + default_ext)
                
            worker = ZapReportExportWorker(
                self, 
                output_file,
                str(self.title_field.getText()),
                template,
                str(self.api_key_field.getText()),
                str(self.port_field.getText())
            )
            worker.execute()

    def generate_report(self, event):
        if not self._verify_config():
            return
            
        self.report_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self._log("Starting report generation...")
        
        self.report_tabs_panel.removeAll()
        self.details_tabs.removeAll()
        self._init_empty_details_tab()
        self.report_tabs_panel.add(JLabel("Generating report, please wait..."))
        self.report_tabs_panel.revalidate()
        
        worker = ReportWorker(self)
        worker.execute()

    def _get_zap_alerts(self):
        try:
            url = "http://127.0.0.1:%s/JSON/alert/view/alerts/?apikey=%s" % (
                self.saved_config['zap_port'], 
                self.saved_config['zap_api_key'])
            self._log("Fetching alerts from ZAP...")
            response = self._http_request(url)
            
            if 'error' in response:
                self._log("ZAP API error: %s" % response['error'])
                return []
                
            alerts = response.get('alerts', [])
            
            for alert in alerts:
                message_id = alert.get('messageId')
                if message_id:
                    request, response = self._get_message_details(message_id)
                    alert['request'] = request or "Not available"
                    alert['response'] = response or "Not available"
            
            return alerts
        except Exception as e:
            self._log("Error fetching alerts: %s" % str(e))
            return []

    def _get_message_details(self, message_id):
        try:
            if not message_id:
                return None, None
                
            message_url = "http://127.0.0.1:%s/JSON/core/view/message/?apikey=%s&id=%s" % (
                self.saved_config['zap_port'],
                self.saved_config['zap_api_key'],
                message_id)
            message_data = self._http_request(message_url)
            
            if 'error' in message_data:
                self._log("Error getting message details: %s" % message_data['error'])
                return None, None
                
            msg = message_data.get('message', {})
            
            request_header = msg.get('requestHeader', '')
            request_body = msg.get('requestBody', '')
            request = request_header
            if request_body:
                request += "\r\n\r\n" + request_body
                
            response_header = msg.get('responseHeader', '')
            response_body = msg.get('responseBody', '')
            response = response_header
            if response_body:
                response += "\r\n\r\n" + response_body
                
            return request.strip(), response.strip()
        except Exception as e:
            self._log("Error getting message details: %s" % str(e))
            return None, None

    def _create_summary_tab(self, tabbed_pane, alerts):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Informational': 0
        }
        
        for alert in alerts:
            risk = alert.get('risk')
            if risk in counts:
                counts[risk] += 1

        model = DefaultTableModel(
            [
                ["Critical", counts['Critical'], "Immediate threats"],
                ["High", counts['High'], "Serious vulnerabilities"],
                ["Medium", counts['Medium'], "Should be addressed"],
                ["Low", counts['Low'], "Low priority issues"],
                ["Informational", counts['Informational'], "FYI findings"]
            ],
            ["Severity", "Count", "Description"]
        )

        table = JTable(model)
        table.setFont(Font("Arial", Font.PLAIN, 12))
        table.setRowHeight(25)

        class SummaryRenderer(DefaultTableCellRenderer):
            COLOR_MAP = {
                'Critical': Color(255, 102, 102),
                'High': Color(255, 153, 51),
                'Medium': Color(255, 255, 102),
                'Low': Color(173, 216, 230),
                'Informational': Color(220, 220, 220)
            }

            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                component = DefaultTableCellRenderer.getTableCellRendererComponent(
                    self, table, value, isSelected, hasFocus, row, column)
                component.setHorizontalAlignment(JLabel.CENTER)
                
                if not isSelected:
                    severity = table.getModel().getValueAt(row, 0)
                    component.setBackground(self.COLOR_MAP.get(severity, Color.WHITE))
                return component

        renderer = SummaryRenderer()
        for i in range(table.getColumnCount()):
            table.getColumnModel().getColumn(i).setCellRenderer(renderer)

        scroll_pane = JScrollPane(table)
        panel.add(scroll_pane)
        tabbed_pane.addTab("Summary", panel)

    def _create_detail_tabs(self, tabbed_pane, alerts):
        risk_levels = ['Critical', 'High', 'Medium', 'Low', 'Informational']
        
        for risk in risk_levels:
            risk_alerts = [a for a in alerts if a.get('risk') == risk]
            if not risk_alerts:
                continue
                
            risk_panel = JPanel()
            risk_panel.setLayout(BoxLayout(risk_panel, BoxLayout.Y_AXIS))
            risk_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

            control_panel = JPanel()
            control_panel.setLayout(BoxLayout(control_panel, BoxLayout.X_AXIS))
            
            control_panel.add(JLabel("Items per page:"))
            self.page_size_combo = JComboBox([10, 25, 50, 100])
            self.page_size_combo.setSelectedItem(self.page_size)
            self.page_size_combo.addActionListener(self._update_page_size)
            control_panel.add(self.page_size_combo)
            
            control_panel.add(Box.createHorizontalStrut(20))
            self.prev_btn = JButton("< Previous", actionPerformed=self._prev_page)
            control_panel.add(self.prev_btn)
            
            self.page_label = JLabel("Page 1 of 1")
            control_panel.add(self.page_label)
            
            self.next_btn = JButton("Next >", actionPerformed=self._next_page)
            control_panel.add(self.next_btn)
            
            risk_panel.add(control_panel)
            
            self.current_alerts = risk_alerts
            self.current_risk_level = risk
            
            self._create_paginated_table(risk_panel, risk, 1)
            
            tab_title = "%s (%d)" % (risk, len(risk_alerts))
            tabbed_pane.addTab(tab_title, None, risk_panel, "%s severity vulnerabilities" % risk)

    def _create_paginated_table(self, panel, risk_level, page):
        if hasattr(self, 'current_table_panel'):
            panel.remove(self.current_table_panel)

        start_idx = (page - 1) * self.page_size
        end_idx = min(start_idx + self.page_size, len(self.current_alerts))
        page_alerts = self.current_alerts[start_idx:end_idx]

        table_data = []
        for alert in page_alerts:
            table_data.append([
                alert.get('name'),
                alert.get('url'),
                alert.get('description', ''),
                alert.get('solution', ''),
                alert.get('cweid', ''),
                alert.get('request', ''),
                alert.get('response', '')
            ])

        model = DefaultTableModel(table_data, [
            "Vulnerability", "URL", "Description", "Solution", "CWE ID", "Request", "Response"
        ])

        table = JTable(model)
        table.setFont(Font("Arial", Font.PLAIN, 12))

        table.getSelectionModel().addListSelectionListener(
            lambda event, t=table, r=risk_level: self._show_selected_row_details(t, r) if not event.getValueIsAdjusting() else None
        )

        class SelectionRenderer(DefaultTableCellRenderer):
            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                component = DefaultTableCellRenderer.getTableCellRendererComponent(
                    self, table, value, isSelected, hasFocus, row, column)
                component.setBackground(Color(210, 230, 255) if isSelected else Color.WHITE)
                component.setForeground(Color.BLACK)
                return component

        table.setDefaultRenderer(Object, SelectionRenderer())

        scroll_pane = JScrollPane(table)
        self.current_table_panel = JPanel()
        self.current_table_panel.setLayout(BoxLayout(self.current_table_panel, BoxLayout.Y_AXIS))
        self.current_table_panel.add(scroll_pane)
        panel.add(self.current_table_panel)

        total_pages = (len(self.current_alerts) // self.page_size) + (1 if len(self.current_alerts) % self.page_size > 0 else 0)
        self.page_label.setText("Page %d of %d" % (page, total_pages))
        self.prev_btn.setEnabled(page > 1)
        self.next_btn.setEnabled(page < total_pages)

        self.current_page = page

        panel.revalidate()
        panel.repaint()

    def _update_page_size(self, event):
        self.page_size = int(self.page_size_combo.getSelectedItem())
        self._create_paginated_table(self.current_table_panel.getParent(), self.current_risk_level, 1)

    def _prev_page(self, event):
        if self.current_page > 1:
            self._create_paginated_table(self.current_table_panel.getParent(), self.current_risk_level, self.current_page - 1)

    def _next_page(self, event):
        total_pages = (len(self.current_alerts) // self.page_size) + (1 if len(self.current_alerts) % self.page_size > 0 else 0)
        if self.current_page < total_pages:
            self._create_paginated_table(self.current_table_panel.getParent(), self.current_risk_level, self.current_page + 1)

    def _show_selected_row_details(self, table, risk_level):
        selected_row = table.getSelectedRow()
        if selected_row == -1:
            return

        model = table.getModel()
        request = model.getValueAt(selected_row, 5)
        response = model.getValueAt(selected_row, 6)
        
        def update_details():
            self.req_text.setText(str(request) if request else "No request available")
            self.resp_text.setText(str(response) if response else "No response available")
            self.req_text.setCaretPosition(0)
            self.resp_text.setCaretPosition(0)
        
        EventQueue.invokeLater(update_details)

    def _http_request(self, url):
        try:
            req = urllib2.Request(url)
            response = urllib2.urlopen(req, timeout=15)
            return json.loads(response.read())
        except urllib2.HTTPError as e:
            return {'error': 'HTTP Error: %s %s' % (e.code, e.reason)}
        except urllib2.URLError as e:
            return {'error': 'URL Error: %s' % e.reason}
        except ValueError as e:
            return {'error': 'JSON parse error: %s' % str(e)}
        except Exception as e:
            return {'error': 'Unexpected error: %s' % str(e)}

    def _load_setting(self, key, default):
        try:
            value = self.callbacks.loadExtensionSetting(key)
            return value if value is not None else default
        except Exception as e:
            self._log("Error loading setting %s: %s" % (key, str(e)))
            return default
            
    def _save_setting(self, key, value):
        try:
            self.callbacks.saveExtensionSetting(key, value)
            self._log("Saved setting: %s=%s" % (key, value))
            return True
        except Exception as e:
            self._log("Error saving setting %s: %s" % (key, str(e)))
            return False
            
    def _save_config(self, event):
        config = {
            'zap_api_key': self.api_key_field.getText(),
            'zap_port': self.port_field.getText()
        }
        
        try:
            int(config['zap_port'])
        except ValueError:
            self._log("Error: Port must be a number")
            return
            
        success = True
        for key, value in config.items():
            if not self._save_setting(key, value):
                success = False
                
        if success:
            self.saved_config = config
            self._log("Configuration saved successfully")
        else:
            self._log("Error: Failed to save some configuration values")

    def _verify_config(self):
        if not self.saved_config['zap_api_key']:
            self._log("Error: API key not configured")
            return False
        if not self.saved_config['zap_port']:
            self._log("Error: Port not configured")
            return False
        return True

    def _log(self, message):
        def _append():
            self.output_area.append(message + "\n")
            self.output_area.setCaretPosition(self.output_area.getDocument().getLength())
        EventQueue.invokeLater(_append)

    def getTabCaption(self):
        return "ZAP Reporter"
    
    def getUiComponent(self):
        return self.panel

class ReportWorker(SwingWorker):
    def __init__(self, extender):
        self.extender = extender
        self.alerts = []
        
    def doInBackground(self):
        try:
            self.alerts = self.extender._get_zap_alerts()
            return True
        except Exception as e:
            self.extender._log("Error in background task: %s" % str(e))
            return False
    
    def done(self):
        try:
            success = self.get()
            if not success or not self.alerts:
                self.extender._log("Report generation failed or no alerts found")
                self.extender.report_tabs_panel.removeAll()
                self.extender.report_tabs_panel.add(JLabel("No vulnerabilities found"))
                self.extender.report_tabs_panel.revalidate()
                return
                
            report_tabs = JTabbedPane()
            self.extender._create_summary_tab(report_tabs, self.alerts)
            self.extender._create_detail_tabs(report_tabs, self.alerts)
            
            self.extender.report_tabs_panel.removeAll()
            self.extender.report_tabs_panel.add(report_tabs)
            self.extender.report_tabs_panel.revalidate()
            self.extender.results_split.setDividerLocation(0.7)
            
            self.extender.current_alerts = self.alerts
            self.extender.export_btn.setEnabled(True)
            self.extender._log("Report generated successfully")
            
        except Exception as e:
            self.extender._log("Error completing report: %s" % str(e))
        finally:
            self.extender.report_btn.setEnabled(True)   
    
class ZapReportExportWorker(SwingWorker):
    def __init__(self, extender, output_file, title, template, api_key, port):
        self.extender = extender
        self.output_file = output_file
        self.title = title
        self.template = template
        self.api_key = api_key
        self.port = port
        
    def doInBackground(self):
        """Generate report using ZAP's built-in report endpoint"""
        try:
            # Build the report URL with parameters
            params = {
                'apikey': self.api_key,
                'title': url_quote(self.title),
                'template': self.template,
                'reportFileName': url_quote(self.output_file.getName()),
                'reportDir': url_quote(self.output_file.getParent().replace('\\', '/')),
                'display': 'false'
            }
            
            # Remove empty parameters
            params = {k: v for k, v in params.items() if v}
            
            url = "http://127.0.0.1:%s/JSON/reports/action/generate?" % self.port
            url += "&".join(["%s=%s" % (k, v) for k, v in params.items()])
            
            self.extender._log("Generating report using ZAP API...")
            self.extender._log("URL: %s" % url)  # Debug log
            
            response = urllib2.urlopen(url, timeout=120)  # Increased timeout
            result = json.loads(response.read())
            
            # More flexible success checking
            if result.get('Result') == 'OK' or 'OK' in str(result):
                # Verify file was actually created
                if self.output_file.exists():
                    return True
                else:
                    self.extender._log("Report file not found at: %s" % self.output_file.getAbsolutePath())
                    return False
            else:
                error_msg = result.get('message', 'Unknown error')
                if not error_msg:
                    error_msg = str(result)
                self.extender._log("Report generation failed. Response: %s" % error_msg)
                return False
                
        except urllib2.HTTPError as e:
            error_content = e.read()
            try:
                error_json = json.loads(error_content)
                error_msg = error_json.get('message', error_content)
            except:
                error_msg = error_content
            self.extender._log("HTTP Error (%s): %s" % (e.code, error_msg))
            return False
            
        except urllib2.URLError as e:
            self.extender._log("URL Error: %s" % e.reason)
            return False
            
        except Exception as e:
            self.extender._log("Unexpected error: %s" % str(e))
            return False
    
    def done(self):
        """Handle completion of report generation"""
        try:
            success = self.get()
            if success:
                self.extender._log("Successfully exported report to: %s" % 
                                 self.output_file.getAbsolutePath())
            else:
                self.extender._log("Failed to generate report. Check ZAP logs for details.")
        except Exception as e:
            self.extender._log("Error completing export: %s" % str(e))