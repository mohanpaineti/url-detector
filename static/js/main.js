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
        
        // Extract conclusion if present
        let formattedAnalysis = result.details;
        let conclusionText = null;
        
        // Look for conclusion patterns in the analysis
        const conclusionPattern = /(?:CONCLUSION|FINAL CONCLUSION):\s*This URL is\s*(MALICIOUS|SAFE)/i;
        const conclusionMatch = formattedAnalysis.match(conclusionPattern);
        
        if (conclusionMatch) {
            conclusionText = conclusionMatch[0];
            const safeOrMalicious = conclusionMatch[1].toUpperCase();
            
            // Create conclusion element
            const conclusionElement = document.createElement('div');
            conclusionElement.classList.add('analysis-conclusion');
            
            if (safeOrMalicious === 'SAFE') {
                conclusionElement.classList.add('conclusion-safe');
                conclusionElement.innerHTML = `<i class="fas fa-shield-alt"></i> ${conclusionText}`;
            } else {
                conclusionElement.classList.add('conclusion-malicious');
                conclusionElement.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${conclusionText}`;
            }
            
            resultDiv.appendChild(conclusionElement);
        }
        
        // Create analysis container
        const analysisContent = document.createElement('div');
        analysisContent.classList.add('analysis-content');
        
        // Convert markdown to HTML instead of simple line breaks
        analysisContent.innerHTML = marked.parse(formattedAnalysis);
        
        // URL display
        const urlDisplay = document.createElement('div');
        urlDisplay.classList.add('result-url');
        urlDisplay.textContent = `Analyzed URL: ${result.url}`;
        urlDisplay.style.marginTop = '1rem';
        urlDisplay.style.wordBreak = 'break-all';
        urlDisplay.style.fontSize = '0.875rem';
        urlDisplay.style.color = 'var(--text-muted)';
        
        // Put it all together
        resultDiv.appendChild(analysisContent);
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