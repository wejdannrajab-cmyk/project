/**
 * Generate sensor data via AJAX
 */
function generateSensorData() {
    fetch(`${API_BASE_URL}/generate_sensor_data.php`, {
        method: 'POST',
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log(`Generated data for ${data.generated} patients`);
            updateLastRefreshTime();
        }
    });
}
