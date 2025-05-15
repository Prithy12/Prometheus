/**
 * NetGuardian Dashboard Application
 * 
 * This file handles all the dashboard functionality including:
 * - Authentication with the API Gateway
 * - Fetching and displaying security events
 * - Fetching and displaying threat intelligence
 * - Chart generation and event filtering
 */

// Development mode flag - set to true to use mock data instead of API calls
const DEV_MODE = false;

// Mock data for development
const MOCK_DATA = {
  events: [
    {
      event_id: "123e4567-e89b-12d3-a456-426614174000",
      timestamp: "2025-05-14T12:00:00.000Z",
      source_ip: "192.168.1.100",
      source_port: 54321,
      destination_ip: "10.0.0.1",
      destination_port: 443,
      protocol: "TCP",
      event_type: "intrusion_attempt",
      severity: 8,
      description: "Possible SQL injection attempt detected",
      raw_data: JSON.stringify({
        request_path: "/admin/login.php",
        query_string: "id=1' OR 1=1--",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
      })
    },
    {
      event_id: "223e4567-e89b-12d3-a456-426614174001",
      timestamp: "2025-05-14T11:45:00.000Z",
      source_ip: "10.0.0.14",
      source_port: 51234,
      destination_ip: "10.0.0.5",
      destination_port: 22,
      protocol: "TCP",
      event_type: "credential_access",
      severity: 7,
      description: "Multiple failed SSH login attempts",
      raw_data: JSON.stringify({
        username: "admin",
        attempt_count: 5,
        auth_method: "password"
      })
    },
    {
      event_id: "323e4567-e89b-12d3-a456-426614174002",
      timestamp: "2025-05-14T10:30:00.000Z",
      source_ip: "192.168.2.54",
      source_port: 0,
      destination_ip: "192.168.1.0/24",
      destination_port: 0,
      protocol: "ICMP",
      event_type: "reconnaissance",
      severity: 4,
      description: "Network scan detected",
      raw_data: JSON.stringify({
        scan_type: "ICMP sweep",
        ports_scanned: [],
        duration: 45
      })
    },
    {
      event_id: "423e4567-e89b-12d3-a456-426614174003",
      timestamp: "2025-05-14T09:15:00.000Z",
      source_ip: "unknown",
      source_port: 0,
      destination_ip: "10.0.0.23",
      destination_port: 0,
      protocol: "",
      event_type: "malware_detection",
      severity: 9,
      description: "Ransomware detected on employee workstation",
      raw_data: JSON.stringify({
        malware_name: "CryptoLock",
        file_path: "C:\\Users\\john\\Downloads\\invoice.exe",
        file_hash: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        action_taken: "quarantined"
      })
    },
    {
      event_id: "523e4567-e89b-12d3-a456-426614174004",
      timestamp: "2025-05-14T08:45:00.000Z",
      source_ip: "10.0.0.45",
      source_port: 49876,
      destination_ip: "203.0.113.25",
      destination_port: 8080,
      protocol: "TCP",
      event_type: "command_and_control",
      severity: 9,
      description: "Command & Control traffic detected",
      raw_data: JSON.stringify({
        connection_count: 12,
        data_transferred: "245KB",
        domain: "malicious-c2.example.com"
      })
    },
    {
      event_id: "623e4567-e89b-12d3-a456-426614174005",
      timestamp: "2025-05-14T07:30:00.000Z",
      source_ip: "10.0.0.12",
      source_port: 52468,
      destination_ip: "10.0.0.2",
      destination_port: 3389,
      protocol: "TCP",
      event_type: "lateral_movement",
      severity: 7,
      description: "Suspicious RDP connection to server",
      raw_data: JSON.stringify({
        user: "support",
        duration: "25m",
        outside_business_hours: true
      })
    },
    {
      event_id: "723e4567-e89b-12d3-a456-426614174006",
      timestamp: "2025-05-13T18:20:00.000Z",
      source_ip: "10.0.0.17",
      source_port: 0,
      destination_ip: "",
      destination_port: 0,
      protocol: "",
      event_type: "privilege_escalation",
      severity: 8,
      description: "User added to administrator group",
      raw_data: JSON.stringify({
        username: "guest",
        added_by: "system",
        method: "group policy modification"
      })
    },
    {
      event_id: "823e4567-e89b-12d3-a456-426614174007",
      timestamp: "2025-05-13T16:45:00.000Z",
      source_ip: "10.0.0.34",
      source_port: 55123,
      destination_ip: "172.16.0.5",
      destination_port: 1521,
      protocol: "TCP",
      event_type: "data_exfiltration",
      severity: 10,
      description: "Large database query with external transfer",
      raw_data: JSON.stringify({
        database: "customers",
        query_size: "15MB",
        records_accessed: 50000
      })
    },
    {
      event_id: "923e4567-e89b-12d3-a456-426614174008",
      timestamp: "2025-05-13T14:30:00.000Z",
      source_ip: "192.168.1.220",
      source_port: 51234,
      destination_ip: "10.0.0.5",
      destination_port: 445,
      protocol: "TCP",
      event_type: "defense_evasion",
      severity: 8,
      description: "Security service stopped on server",
      raw_data: JSON.stringify({
        service: "AV Protection",
        user: "SYSTEM",
        method: "service control manager"
      })
    },
    {
      event_id: "023e4567-e89b-12d3-a456-426614174009",
      timestamp: "2025-05-13T12:15:00.000Z",
      source_ip: "10.0.0.78",
      source_port: 49765,
      destination_ip: "10.0.0.1",
      destination_port: 53,
      protocol: "UDP",
      event_type: "other",
      severity: 3,
      description: "DNS request to suspicious domain",
      raw_data: JSON.stringify({
        domain: "suspicious-analytics.example.com",
        resolution: "203.0.113.100",
        request_count: 15
      })
    }
  ],
  intel: [
    {
      ioc_id: "abc12345-e89b-12d3-a456-426614174000",
      type: "ip",
      value: "203.0.113.25",
      confidence: 85,
      severity: 8,
      first_seen: "2025-05-10T09:15:00.000Z",
      last_seen: "2025-05-14T10:30:00.000Z",
      description: "Known command and control server for BotnetX",
      tags: ["c2", "botnet", "malicious"]
    },
    {
      ioc_id: "bcd12345-e89b-12d3-a456-426614174001",
      type: "domain",
      value: "malicious-c2.example.com",
      confidence: 92,
      severity: 9,
      first_seen: "2025-05-09T14:20:00.000Z",
      last_seen: "2025-05-14T08:45:00.000Z",
      description: "Malware distribution and control domain",
      tags: ["malware", "c2", "ransomware"]
    },
    {
      ioc_id: "cde12345-e89b-12d3-a456-426614174002",
      type: "file_hash",
      value: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
      confidence: 100,
      severity: 9,
      first_seen: "2025-05-08T12:10:00.000Z",
      last_seen: "2025-05-14T09:15:00.000Z",
      description: "CryptoLock ransomware executable",
      tags: ["ransomware", "malware", "trojan"]
    },
    {
      ioc_id: "def12345-e89b-12d3-a456-426614174003",
      type: "url",
      value: "https://phishing.example.com/login/",
      confidence: 90,
      severity: 7,
      first_seen: "2025-05-11T18:30:00.000Z",
      last_seen: "2025-05-13T22:15:00.000Z",
      description: "Phishing page impersonating corporate login",
      tags: ["phishing", "credential-theft"]
    },
    {
      ioc_id: "efg12345-e89b-12d3-a456-426614174004",
      type: "email",
      value: "attacker@malicious-sender.com",
      confidence: 75,
      severity: 6,
      first_seen: "2025-05-12T08:45:00.000Z",
      last_seen: "2025-05-14T11:20:00.000Z",
      description: "Sender of spear phishing emails with malicious attachments",
      tags: ["phishing", "initial-access"]
    },
    {
      ioc_id: "fgh12345-e89b-12d3-a456-426614174005",
      type: "ip",
      value: "192.168.2.54",
      confidence: 60,
      severity: 4,
      first_seen: "2025-05-14T10:30:00.000Z",
      last_seen: "2025-05-14T10:30:00.000Z",
      description: "Internal host conducting network scanning",
      tags: ["reconnaissance", "internal"]
    },
    {
      ioc_id: "ghi12345-e89b-12d3-a456-426614174006",
      type: "user_agent",
      value: "ScanBot/1.0",
      confidence: 70,
      severity: 5,
      first_seen: "2025-05-13T09:10:00.000Z",
      last_seen: "2025-05-14T12:30:00.000Z",
      description: "Non-standard user agent associated with scanning tools",
      tags: ["scanner", "recon"]
    }
  ],
  stats: {
    totalEvents: 157,
    highSeverity: 28,
    mediumSeverity: 64,
    lowSeverity: 65
  },
  user: {
    id: 1,
    username: 'admin',
    email: 'admin@netguardian.org',
    role: 'admin',
    token: 'mock-jwt-token-for-development'
  }
};

// API endpoint constants
const API_BASE_URL = '/api';
const API_ENDPOINTS = {
  LOGIN: `${API_BASE_URL}/auth/login`,
  EVENTS: `${API_BASE_URL}/events`,
  EVENTS_SUMMARY: `${API_BASE_URL}/events/summary`,
  INTEL: `${API_BASE_URL}/intel/iocs`,
};

// Main dashboard application
function dashboard() {
  return {
    // Authentication state
    isAuthenticated: DEV_MODE ? true : false,
    user: DEV_MODE ? MOCK_DATA.user : null,
    token: DEV_MODE ? MOCK_DATA.user.token : null,
    loginForm: {
      username: '',
      password: '',
      error: null,
      loading: false
    },
    
    // Events data
    events: DEV_MODE ? MOCK_DATA.events : [],
    filteredEvents: [],
    currentPage: 1,
    limit: 10,
    hasMoreEvents: false,
    
    // Intel data
    intel: DEV_MODE ? MOCK_DATA.intel : [],
    filteredIntel: [],
    
    // Filters
    filters: {
      search: '',
      eventType: '',
      severity: ''
    },
    intelFilters: {
      search: '',
      type: ''
    },
    
    // Summary statistics
    stats: {
      totalEvents: 0,
      highSeverity: 0,
      mediumSeverity: 0,
      lowSeverity: 0
    },
    
    // Charts
    eventsByTypeChart: null,
    eventsBySeverityChart: null,
    
    // Modals
    showEventModal: false,
    selectedEvent: null,
    showIntelModal: false,
    selectedIntel: null,
    
    // Lifecycle methods
    init() {
      // If not in dev mode, check for existing authentication
      if (!DEV_MODE) {
        this.checkAuth();
      }
      
      // Load initial data
      this.loadData();
      
      // Initialize charts after data is loaded
      this.$nextTick(() => {
        this.initCharts();
      });
    },
    
    // Handle login
    async login() {
      if (DEV_MODE) {
        this.isAuthenticated = true;
        this.user = MOCK_DATA.user;
        this.token = MOCK_DATA.user.token;
        return;
      }
      
      this.loginForm.loading = true;
      this.loginForm.error = null;
      
      try {
        const response = await fetch(API_ENDPOINTS.LOGIN, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            username: this.loginForm.username,
            password: this.loginForm.password
          })
        });
        
        if (!response.ok) {
          throw new Error('Authentication failed');
        }
        
        const data = await response.json();
        
        // Store auth data
        this.isAuthenticated = true;
        this.user = data.user;
        this.token = data.token;
        
        // Store token in local storage
        localStorage.setItem('token', data.token);
        
        // Load data after successful login
        this.loadData();
      } catch (error) {
        this.loginForm.error = error.message || 'Login failed';
        console.error('Login error:', error);
      } finally {
        this.loginForm.loading = false;
      }
    },
    
    // Check for existing authentication
    checkAuth() {
      const token = localStorage.getItem('token');
      
      if (token) {
        // Validate token (could make an API call to validate)
        this.token = token;
        this.isAuthenticated = true;
        
        // TODO: Fetch user data from token or API
      }
    },
    
    // Handle logout
    logout() {
      this.isAuthenticated = false;
      this.user = null;
      this.token = null;
      localStorage.removeItem('token');
    },
    
    // Load all dashboard data
    async loadData() {
      if (DEV_MODE) {
        this.events = MOCK_DATA.events;
        this.filteredEvents = this.events;
        this.stats = MOCK_DATA.stats;
        this.intel = MOCK_DATA.intel;
        this.filteredIntel = this.intel;
        return;
      }
      
      try {
        // Load data in parallel
        await Promise.all([
          this.fetchEvents(),
          this.fetchStats(),
          this.fetchIntel()
        ]);
      } catch (error) {
        console.error('Error loading data:', error);
      }
    },
    
    /**
     * Fetch security events from API
     */
    async fetchEvents() {
      if (DEV_MODE) {
        // In development mode, use mock data
        this.events = [...MOCK_DATA.events]; // Create a copy to avoid mutations
        this.filteredEvents = this.events;
        
        // Simulate pagination
        this.hasMoreEvents = false;
        
        // Apply search filter if needed
        if (this.filters.search) {
          this.filterEvents();
        }
        return;
      }
      
      try {
        const offset = (this.currentPage - 1) * this.limit;
        const queryParams = new URLSearchParams({
          limit: this.limit,
          offset: offset
        });
        
        if (this.filters.eventType) {
          queryParams.append('event_type', this.filters.eventType);
        }
        
        if (this.filters.severity === 'high') {
          queryParams.append('severity', 8); // Minimum severity for high
        } else if (this.filters.severity === 'medium') {
          queryParams.append('severity', 4); // Minimum severity for medium
        } else if (this.filters.severity === 'low') {
          queryParams.append('severity', 1); // Minimum severity for low
        }
        
        const response = await fetch(`${API_ENDPOINTS.EVENTS}?${queryParams.toString()}`, {
          headers: {
            'Authorization': `Bearer ${this.token}`
          }
        });
        
        if (!response.ok) {
          throw new Error('Failed to fetch events');
        }
        
        const data = await response.json();
        this.events = data.data.events || [];
        this.filteredEvents = this.events;
        
        // Check if there are more events
        this.hasMoreEvents = this.events.length === this.limit;
        
        // Apply search filter if needed
        if (this.filters.search) {
          this.filterEvents();
        }
        
      } catch (error) {
        console.error('Error fetching events:', error);
      }
    },
    
    /**
     * Fetch threat intelligence data
     */
    async fetchIntel() {
      if (DEV_MODE) {
        // In development mode, use mock data
        this.intel = [...MOCK_DATA.intel]; // Create a copy to avoid mutations
        this.filteredIntel = this.intel;
        
        // Apply search filter if needed
        if (this.intelFilters.search) {
          this.filterIntel();
        }
        return;
      }
      
      try {
        const queryParams = new URLSearchParams({
          limit: 100
        });
        
        if (this.intelFilters.type) {
          queryParams.append('type', this.intelFilters.type);
        }
        
        const response = await fetch(`${API_ENDPOINTS.INTEL}?${queryParams.toString()}`, {
          headers: {
            'Authorization': `Bearer ${this.token}`
          }
        });
        
        if (!response.ok) {
          throw new Error('Failed to fetch intel');
        }
        
        const data = await response.json();
        this.intel = data.data.iocs || [];
        this.filteredIntel = this.intel;
        
        // Apply search filter if needed
        if (this.intelFilters.search) {
          this.filterIntel();
        }
        
      } catch (error) {
        console.error('Error fetching intel:', error);
      }
    },
    
    /**
     * Fetch summary statistics
     */
    async fetchStats() {
      if (DEV_MODE) {
        // In development mode, use mock data
        this.stats = { ...MOCK_DATA.stats }; // Create a copy to avoid mutations
        return;
      }
      
      try {
        const response = await fetch(API_ENDPOINTS.EVENTS_SUMMARY, {
          headers: {
            'Authorization': `Bearer ${this.token}`
          }
        });
        
        if (!response.ok) {
          throw new Error('Failed to fetch statistics');
        }
        
        const data = await response.json();
        const summary = data.data.summary;
        
        // Update stats based on summary data
        this.stats.totalEvents = summary.totalEvents || 0;
        this.stats.highSeverity = summary.severityCounts?.high || 0;
        this.stats.mediumSeverity = summary.severityCounts?.medium || 0;
        this.stats.lowSeverity = summary.severityCounts?.low || 0;
        
      } catch (error) {
        console.error('Error fetching statistics:', error);
        
        // Set default stats by calculating from events if summary API fails
        this.calculateStatsFromEvents();
      }
    },
    
    /**
     * Calculate statistics from event data as a fallback
     */
    calculateStatsFromEvents() {
      this.stats.totalEvents = this.events.length;
      this.stats.highSeverity = this.events.filter(e => e.severity >= 8).length;
      this.stats.mediumSeverity = this.events.filter(e => e.severity >= 4 && e.severity < 8).length;
      this.stats.lowSeverity = this.events.filter(e => e.severity < 4).length;
    },
    
    /**
     * Initialize charts
     */
    initCharts() {
      this.initEventsByTypeChart();
      this.initEventsBySeverityChart();
    },
    
    /**
     * Initialize events by type chart
     */
    initEventsByTypeChart() {
      // Group events by type
      const eventTypes = {};
      this.events.forEach(event => {
        const type = event.event_type || 'unknown';
        eventTypes[type] = (eventTypes[type] || 0) + 1;
      });
      
      // Prepare chart data
      const labels = Object.keys(eventTypes).map(type => this.formatEventType(type));
      const data = Object.values(eventTypes);
      
      // Destroy previous chart if exists
      if (this.eventsByTypeChart) {
        this.eventsByTypeChart.destroy();
      }
      
      // Create chart
      const ctx = document.getElementById('eventsByTypeChart').getContext('2d');
      this.eventsByTypeChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: labels,
          datasets: [{
            label: 'Event Count',
            data: data,
            backgroundColor: '#3498db',
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              beginAtZero: true,
              ticks: {
                precision: 0
              }
            }
          }
        }
      });
    },
    
    /**
     * Initialize events by severity chart
     */
    initEventsBySeverityChart() {
      // Prepare chart data
      const data = [
        this.stats.lowSeverity,
        this.stats.mediumSeverity,
        this.stats.highSeverity
      ];
      
      // Destroy previous chart if exists
      if (this.eventsBySeverityChart) {
        this.eventsBySeverityChart.destroy();
      }
      
      // Create chart
      const ctx = document.getElementById('eventsBySeverityChart').getContext('2d');
      this.eventsBySeverityChart = new Chart(ctx, {
        type: 'pie',
        data: {
          labels: ['Low', 'Medium', 'High'],
          datasets: [{
            data: data,
            backgroundColor: [
              '#2ecc71',
              '#f39c12',
              '#e74c3c'
            ],
            borderWidth: 1
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false
        }
      });
    },
    
    /**
     * Filter events based on search and filters
     */
    filterEvents() {
      if (!this.filters.search && !this.filters.eventType && !this.filters.severity) {
        this.filteredEvents = this.events;
        return;
      }
      
      this.filteredEvents = this.events.filter(event => {
        // Search filter
        if (this.filters.search) {
          const searchTerm = this.filters.search.toLowerCase();
          const descriptionMatch = event.description && event.description.toLowerCase().includes(searchTerm);
          const sourceIPMatch = event.source_ip && event.source_ip.toLowerCase().includes(searchTerm);
          const destIPMatch = event.destination_ip && event.destination_ip.toLowerCase().includes(searchTerm);
          
          if (!descriptionMatch && !sourceIPMatch && !destIPMatch) {
            return false;
          }
        }
        
        // Event type filter
        if (this.filters.eventType && event.event_type !== this.filters.eventType) {
          return false;
        }
        
        // Severity filter
        if (this.filters.severity) {
          if (this.filters.severity === 'high' && event.severity < 8) {
            return false;
          } else if (this.filters.severity === 'medium' && (event.severity < 4 || event.severity >= 8)) {
            return false;
          } else if (this.filters.severity === 'low' && event.severity >= 4) {
            return false;
          }
        }
        
        return true;
      });
    },
    
    /**
     * Filter intel based on search and filters
     */
    filterIntel() {
      if (!this.intelFilters.search && !this.intelFilters.type) {
        this.filteredIntel = this.intel;
        return;
      }
      
      this.filteredIntel = this.intel.filter(ioc => {
        // Search filter
        if (this.intelFilters.search) {
          const searchTerm = this.intelFilters.search.toLowerCase();
          const valueMatch = ioc.value && ioc.value.toLowerCase().includes(searchTerm);
          const descriptionMatch = ioc.description && ioc.description.toLowerCase().includes(searchTerm);
          
          if (!valueMatch && !descriptionMatch) {
            return false;
          }
        }
        
        // IOC type filter
        if (this.intelFilters.type && ioc.type !== this.intelFilters.type) {
          return false;
        }
        
        return true;
      });
    },
    
    /**
     * View event details
     */
    viewEventDetails(event) {
      this.selectedEvent = event;
      this.showEventModal = true;
    },
    
    /**
     * View intel details
     */
    viewIntelDetails(intel) {
      this.selectedIntel = intel;
      this.showIntelModal = true;
    },
    
    /**
     * Format date for display
     */
    formatDate(dateString) {
      if (!dateString) return 'N/A';
      return new Date(dateString).toLocaleString();
    },
    
    /**
     * Format event type for display
     */
    formatEventType(type) {
      if (!type) return 'Unknown';
      
      return type
        .split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
    },
    
    /**
     * Format IOC type for display
     */
    formatIOCType(type) {
      if (!type) return 'Unknown';
      
      switch (type) {
        case 'ip': return 'IP Address';
        case 'domain': return 'Domain';
        case 'url': return 'URL';
        case 'file_hash': return 'File Hash';
        case 'email': return 'Email';
        case 'user_agent': return 'User Agent';
        default: return type.charAt(0).toUpperCase() + type.slice(1);
      }
    },
    
    /**
     * Format raw data for display
     */
    formatRawData(rawData) {
      if (!rawData) return '';
      
      try {
        // If rawData is a JSON string, parse and format it
        const data = JSON.parse(rawData);
        return JSON.stringify(data, null, 2);
      } catch (e) {
        // If not valid JSON, return as is
        return rawData;
      }
    },
    
    /**
     * Get severity class for CSS
     */
    getSeverityClass(severity) {
      if (severity >= 8) return 'severity-high';
      if (severity >= 4) return 'severity-medium';
      return 'severity-low';
    },
    
    /**
     * Refresh events data
     */
    refreshEvents() {
      // In DEV_MODE, just re-filter the events
      this.filterEvents();
      // If not in dev mode, this would fetch fresh data
      if (!DEV_MODE) {
        this.fetchEvents();
      }
    },
    
    /**
     * Refresh intel data
     */
    refreshIntel() {
      // In DEV_MODE, just re-filter the intel data
      this.filterIntel();
      // If not in dev mode, this would fetch fresh data
      if (!DEV_MODE) {
        this.fetchIntel();
      }
    },
    
    /**
     * Navigate to previous page
     */
    prevPage() {
      if (this.currentPage > 1) {
        this.currentPage--;
        this.fetchEvents();
      }
    },
    
    /**
     * Navigate to next page
     */
    nextPage() {
      if (this.hasMoreEvents) {
        this.currentPage++;
        this.fetchEvents();
      }
    }
  };
}