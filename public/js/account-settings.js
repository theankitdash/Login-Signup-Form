document.addEventListener('DOMContentLoaded', function() {
    
    fetch('/Details') // Endpoint to get the current user's Details
        .then(response => {
            if (response.ok) {
                return response.json();
            } else {
                throw new Error('Failed to fetch current credentials');
            }
        })
        .then(data => {
            document.getElementById('phoneNumber').innerText = data.phone;
            document.getElementById('newPassword').value = ''; // Clear the new password field

            // Display personal details
            document.getElementById('name').value = data.name || '';
            document.getElementById('gender').value = data.gender || '';
            document.getElementById('dateOfBirth').value = formatDate(data.dateOfBirth) || '';
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while fetching current credentials');
        });

    // Function to format date as YYYY-MM-DD
    function formatDate(date) {
        if (!date) return ''; 
        const d = new Date(date);
        const year = d.getFullYear();
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    }    

    //Change password button
    const changePasswordBtn = document.getElementById('changePasswordBtn');
    changePasswordBtn.addEventListener('click', function() {
        const newPassword = document.getElementById('newPassword').value;

        // Send request to change password
        fetch('/changePassword', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ newPassword })
        })
        .then(response => {
            if (response.ok) {
                return response.json();
            } else {
                throw new Error('Failed to change password');
            }
        })
        .then(data => {
            // Handle successful password change
            console.log('Password changed successfully:', data);
            alert('Password changed successfully');
        })
        .catch(error => {
            // Handle error
            console.error('Error changing password:', error);
            alert('An error occurred while changing password');
        });
    });

    //Save profile details
    const saveProfileBtn = document.getElementById('saveProfileBtn');
    saveProfileBtn.addEventListener('click', function() {
        const name = document.getElementById('name').value;
        const gender = document.getElementById('gender').value;
        const dateOfBirth = document.getElementById('dateOfBirth').value;

        // Send request to save personal details
        fetch('/savePersonalDetails', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name, gender, dateOfBirth })
        })
        .then(response => {
            if (response.ok) {
                return response.json();
            } else {
                throw new Error('Failed to save personal details');
            }
        })
        .then(data => {
            // Handle successful saving of personal details
            console.log('Personal details saved successfully:', data);
            alert('Personal details saved successfully');
        })
        .catch(error => {
            // Handle error
            console.error('Error saving personal details:', error);
            alert('An error occurred while saving personal details');
        });
    });
    
    //Logout button
    const logoutBtn = document.getElementById('logoutBtn');
    logoutBtn.addEventListener('click', function() {
        // Send request to logout
        fetch('/logout')
        .then(response => {
            if (response.redirected) {
                window.location.href = 'http://localhost:3000'; // Redirect to the login page
            } else {
                throw new Error('Failed to logout');
            }
        })
        .catch(error => {
            console.error('Error logging out:', error);
            alert('An error occurred while logging out');
        });
    });
});
