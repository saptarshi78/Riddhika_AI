let typingTimer;
const typingIndicator = document.getElementById('typing-indicator');

// Function to show typing status of the user
function showUserTyping() {
    clearTimeout(typingTimer);
    const message = document.getElementById('message').value.trim();

    if (message !== '') {
        typingIndicator.textContent = `${userName} is typing...`;
    } else {
        typingIndicator.textContent = '';  // Clear indicator if no input
    }

    // Clear the indicator after 2 seconds of inactivity
    typingTimer = setTimeout(() => {
        typingIndicator.textContent = '';
    }, 2000);
}

// Function to send the message to the backend
function sendMessage() {
    const message = document.getElementById('message').value.trim();

    if (message === '') {
        document.getElementById('response').textContent = 'Please type a message!';
        return;  // Prevent sending an empty message
    }

    // Show AI typing indicator
    typingIndicator.textContent = 'Riddhika is typing...';

    fetch('/get_response', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message: message }),
    })
    .then(response => response.json())
    .then(data => {
        // Display the AI response and remove the typing indicator
        document.getElementById('response').textContent = data.response || 'No response from AI.';
        typingIndicator.textContent = '';  // Clear typing indicator after response
    })
    .catch(error => {
        document.getElementById('response').textContent = 'Error communicating with AI.';
        console.error('Error:', error);
        typingIndicator.textContent = '';  // Clear typing indicator on error
    });
}
