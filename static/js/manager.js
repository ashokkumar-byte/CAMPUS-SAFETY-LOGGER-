function makeChart(canvasId, labels, values, type) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || typeof Chart === "undefined") return;

    new Chart(canvas, {
        type: type,
        data: {
            labels: labels,
            datasets: [{
                label: "Incidents",
                data: values
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

document.addEventListener("DOMContentLoaded", () => {
    if (!window.analyticsData || typeof Chart === "undefined") return;

    const status = window.analyticsData.status || [];
    const priority = window.analyticsData.priority || [];
    const types = window.analyticsData.type || [];
    const locations = window.analyticsData.location || [];

    makeChart(
        "statusChart",
        status.map(x => x.status),
        status.map(x => x.count),
        "doughnut"
    );

    makeChart(
        "priorityChart",
        priority.map(x => x.priority),
        priority.map(x => x.count),
        "bar"
    );

    makeChart(
        "typeChart",
        types.map(x => x.incident_type),
        types.map(x => x.count),
        "bar"
    );

    makeChart(
        "locationChart",
        locations.map(x => x.location),
        locations.map(x => x.count),
        "bar"
    );
});
