def analyze_incident(incident_type, location, description):
    """
    Safe local incident analyzer.
    This keeps the project working even when no external LLM API key is configured.

    Later, this function can be replaced with an actual LLM API call.
    """
    text = f"{incident_type} {location} {description}".lower()

    critical_words = [
        "fire", "explosion", "electrical shock", "live wire",
        "major injury", "unconscious", "weapon", "gas leak"
    ]
    high_words = [
        "accident", "injury", "fight", "threat", "harassment",
        "unsafe", "electrical", "smoke", "emergency"
    ]

    if any(word in text for word in critical_words):
        priority = "Critical"
    elif any(word in text for word in high_words):
        priority = "High"
    else:
        priority = "Medium"

    summary = (
        f"{incident_type} reported at {location}. "
        f"The report describes: {description[:180]}"
    )

    if priority == "Critical":
        recommendation = (
            "Treat this as an immediate safety concern. Restrict access if needed "
            "and notify the responsible campus emergency or safety team."
        )
    elif priority == "High":
        recommendation = (
            "Manager should review this report promptly, verify the location, "
            "and assign the appropriate safety team."
        )
    else:
        recommendation = (
            "Review the report, verify the details, and assign an appropriate "
            "team for follow-up."
        )

    return {
        "priority": priority,
        "summary": summary,
        "recommendation": recommendation
    }
