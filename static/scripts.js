function sendMessage() {
    const message = document.getElementById('message').value;
    fetch('/get_response', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message: message }),
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('response').textContent = data.response;
    })
    .catch(error => {
        console.error('Error:', error);
    });
}
