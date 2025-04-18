// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Setup flash messages auto-dismiss
    setupFlashMessages();
    
    // Setup chat interface if on chat page
    if (document.querySelector('.chat-container')) {
        setupChatInterface();
    }
    
    // Setup model selection if on dashboard page
    if (document.querySelector('.models-grid')) {
        setupModelSelection();
    }
    
    // Setup profile page interactions
    if (document.querySelector('.profile-container')) {
        setupProfilePage();
    }
});

// Flash messages auto-dismiss
function setupFlashMessages() {
    const flashMessages = document.querySelectorAll('.flash');
    
    flashMessages.forEach(function(flash) {
        setTimeout(function() {
            flash.style.opacity = '0';
            setTimeout(function() {
                flash.remove();
            }, 300);
        }, 5000);
    });
}

// Chat interface setup
function setupChatInterface() {
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-input');
    const chatMessages = document.querySelector('.chat-messages');
    const modelId = chatForm.getAttribute('data-model-id');
    
    // Scroll to bottom of chat
    scrollToBottom();
    
    // Handle form submission
    chatForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const url = chatInput.value.trim();
        if (url === '') return;
        
        // Add user message to chat
        addMessage('user', url);
        
        // Clear input
        chatInput.value = '';
        
        // Add processing message
        const processingMsg = addStatusMessage('Analyzing URL...');
        
        // Send to backend for detection
        detectUrl(url, modelId)
            .then(function(response) {
                // Remove processing message
                processingMsg.remove();
                
                // Add result message
                addResultMessage(response);
            })
            .catch(function(error) {
                // Remove processing message
                processingMsg.remove();
                
                // Add error message with details if available
                let errorMessage = 'Error: Could not analyze URL. Please try again.';
                if (error && error.message) {
                    errorMessage = error.message;
                }
                addStatusMessage(errorMessage);
                console.error('Detection error:', error);
            });
    });
    
    // Function to detect URL
    async function detectUrl(url, modelId) {
        try {
            // Ensure modelId is an integer
            const parsedModelId = parseInt(modelId, 10);
            
            if (isNaN(parsedModelId)) {
                throw new Error("Invalid model ID format");
            }
            
            const response = await fetch('/detect_url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url, model_id: parsedModelId }),
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                // If we get a response but with error status code
                if (data && data.error && data.details) {
                    throw new Error(`${data.error}: ${data.details}`);
                } else {
                    throw new Error('Server error: ' + response.status);
                }
            }
            
            return data;
        } catch (error) {
            console.error('Detection error:', error);
            throw error;
        }
    }
    
    // Function to add a message to the chat
    function addMessage(type, content) {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message', `message-${type}`);
        messageDiv.textContent = content;
        chatMessages.appendChild(messageDiv);
        scrollToBottom();
        return messageDiv;
    }
    
    // Function to add a status message to the chat
    function addStatusMessage(content) {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message-status');
        messageDiv.textContent = content;
        chatMessages.appendChild(messageDiv);
        scrollToBottom();
        return messageDiv;
    }
    
    // Function to add a result message to the chat
    function addResultMessage(result) {
        const botMessage = addMessage('bot', 'Here\'s the analysis for this URL:');
        
        const resultDiv = document.createElement('div');
        resultDiv.classList.add('message-result');
        
        // Result header with status
        const resultHeader = document.createElement('div');
        resultHeader.classList.add('result-header');
        
        // Title with appropriate icon and color
        const resultTitle = document.createElement('div');
        resultTitle.classList.add('result-title', `result-${result.result}`);
        
        let icon = '';
        if (result.result === 'safe') {
            icon = '<i class="fas fa-shield-alt"></i>';
        } else if (result.result === 'malicious') {
            icon = '<i class="fas fa-exclamation-triangle"></i>';
        } else {
            icon = '<i class="fas fa-question-circle"></i>';
        }
        
        resultTitle.innerHTML = `${icon} ${result.result.toUpperCase()}`;
        
        resultHeader.appendChild(resultTitle);
        
        // Details
        const resultDetails = document.createElement('div');
        resultDetails.classList.add('result-details');
        resultDetails.textContent = result.details;
        
        // Add API key info if result is "uncertain" and contains API key message
        if (result.result === 'uncertain' && result.details.includes('API key not configured')) {
            const apiKeyInfo = document.createElement('div');
            apiKeyInfo.classList.add('api-key-info');
            apiKeyInfo.innerHTML = `<strong>Note:</strong> This is running in demo mode since no API keys are configured. 
            To enable full functionality, add your API keys to the .env file.`;
            apiKeyInfo.style.marginTop = '0.5rem';
            apiKeyInfo.style.padding = '0.5rem';
            apiKeyInfo.style.backgroundColor = 'rgba(255, 193, 7, 0.2)';
            apiKeyInfo.style.borderRadius = '4px';
            resultDetails.appendChild(apiKeyInfo);
        }
        
        // URL display
        const urlDisplay = document.createElement('div');
        urlDisplay.classList.add('result-url');
        urlDisplay.textContent = `Analyzed URL: ${result.url}`;
        urlDisplay.style.marginTop = '0.5rem';
        urlDisplay.style.wordBreak = 'break-all';
        urlDisplay.style.fontSize = '0.875rem';
        urlDisplay.style.color = 'var(--text-muted)';
        
        // Put it all together
        resultDiv.appendChild(resultHeader);
        resultDiv.appendChild(resultDetails);
        resultDiv.appendChild(urlDisplay);
        
        botMessage.appendChild(resultDiv);
        scrollToBottom();
    }
    
    // Scroll to bottom of chat
    function scrollToBottom() {
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
}

// Setup model selection
function setupModelSelection() {
    const modelCards = document.querySelectorAll('.model-card');
    
    modelCards.forEach(function(card) {
        card.addEventListener('click', function() {
            const modelId = this.getAttribute('data-model-id');
            window.location.href = `/chat/${modelId}`;
        });
        
        // Add hover animation
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-8px)';
            this.style.boxShadow = 'var(--shadow-lg)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(-5px)';
            this.style.boxShadow = 'var(--shadow-md)';
        });
    });
}

// Setup profile page
function setupProfilePage() {
    const logoutBtn = document.querySelector('.btn-logout');
    
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            
            if (confirm('Are you sure you want to log out?')) {
                window.location.href = '/logout';
            }
        });
    }
    
    // Get the first letter of the username for the avatar
    const profileAvatar = document.querySelector('.profile-avatar');
    const profileName = document.querySelector('.profile-name');
    
    if (profileAvatar && profileName) {
        const firstLetter = profileName.textContent.trim()[0].toUpperCase();
        profileAvatar.textContent = firstLetter;
    }
} 