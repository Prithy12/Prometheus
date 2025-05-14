/**
 * NetGuardian Dashboard Application
 * 
 * This file handles all the dashboard functionality including:
 * - Authentication with the API Gateway
 * - Fetching and displaying security events
 * - Fetching and displaying threat intelligence
 * - Chart generation and event filtering
 */

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
    isAuthenticated: false,
    user: null,
    token: null,
    loginForm: {
      username: '',
      password: ''
    },
    loginError: null,
    
    // Events data
    events: [],
    filteredEvents: [],
    currentPage: 1,
    limit: 10,
    hasMoreEvents: false,
    
    // Intel data
    intel: [],
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
      // Check for stored auth token
      this.token = localStorage.getItem('token');
      const storedUser = localStorage.getItem('user');
      
      if (this.token && storedUser) {
        this.user = JSON.parse(storedUser);
        this.isAuthenticated = true;
        this.initDashboard();
      }
    },
    
    /**
     * Initialize dashboard after authentication
     */
    async initDashboard() {
      await Promise.all([
        this.fetchEvents(),
        this.fetchIntel(),
        this.fetchStats()
      ]);
      
      this.initCharts();
    },
    
    /**
     * Handle login form submission
     */
    async login() {
      try {
        this.loginError = null;
        
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
        
        const data = await response.json();
        
        if (!response.ok) {
          throw new Error(data.message || 'Login failed');
        }
        
        // Store auth data
        this.token = data.data.token;
        this.user = data.data.user;
        this.isAuthenticated = true;
        
        // Save to local storage
        localStorage.setItem('token', this.token);
        localStorage.setItem('user', JSON.stringify(this.user));
        
        // Clear form
        this.loginForm.username = '';
        this.loginForm.password = '';
        
        // Load dashboard data
        this.initDashboard();
        
      } catch (error) {
        console.error('Login error:', error);
        this.loginError = error.message;
      }
    },
    
    /**
     * Logout user
     */
    logout() {
      this.isAuthenticated = false;
      this.user = null;
      this.token = null;
      localStorage.removeItem('token');
      localStorage.removeItem('user');
    },
    
    /**
     * Fetch security events from API
     */
    async fetchEvents() {
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
     * Refresh events data
     */
    refreshEvents() {
      this.fetchEvents();
    },
    
    /**
     * Refresh intel data
     */
    refreshIntel() {
      this.fetchIntel();
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
    }
  };
} 