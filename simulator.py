"""Fictional, non-operational scam-awareness training scenarios."""


SCENARIOS = (
    {
        "id": "kyc",
        "title": "Fictional example: urgent KYC notice",
        "message": "A fictional bank notice says account access may pause unless KYC is updated through a message link.",
        "warning_signs": [
            "The message creates urgency around account access.",
            "It asks the recipient to act through a message link rather than the official banking app.",
        ],
        "actions": [
            "Open the bank's official app or type its known website address yourself.",
            "Contact the bank using a number printed on your card or official statement.",
        ],
    },
    {
        "id": "job",
        "title": "Fictional example: easy-income job offer",
        "message": "A fictional recruiter promises unusually high daily pay for simple online tasks and asks for an upfront registration fee.",
        "warning_signs": [
            "Guaranteed high earnings for little work are a common lure.",
            "A request for an upfront fee is a serious warning sign.",
        ],
        "actions": [
            "Research the employer using independently found contact details.",
            "Do not pay fees or share identity and banking documents before verifying the employer.",
        ],
    },
    {
        "id": "reward",
        "title": "Fictional example: unexpected reward",
        "message": "A fictional message claims you have won a reward you did not enter for and asks you to provide payment details to claim it.",
        "warning_signs": [
            "An unexpected prize can be used to prompt a quick response.",
            "A legitimate reward should not require sensitive banking credentials to receive it.",
        ],
        "actions": [
            "Check promotions only in the official service or app.",
            "Never share an OTP, PIN, or full payment credentials to claim a reward.",
        ],
    },
    {
        "id": "payment",
        "title": "Fictional example: urgent payment request",
        "message": "A fictional contact sends an unexpected urgent payment request and says there is no time to call and confirm.",
        "warning_signs": [
            "Urgency and discouraging independent confirmation are pressure tactics.",
            "An incoming collect request requires careful review; approving one can send money out.",
        ],
        "actions": [
            "Contact the person through a known number or another trusted channel.",
            "Read the payment app's confirmation screen carefully and decline requests you did not initiate.",
        ],
    },
    {
        "id": "remote-access",
        "title": "Fictional example: remote-access request",
        "message": "A fictional support caller says a remote-control app is needed to resolve a payment issue and asks you to keep the call private.",
        "warning_signs": [
            "Unsolicited remote-control access can expose messages and banking activity.",
            "Pressure to keep the request secret reduces the chance of independent verification.",
        ],
        "actions": [
            "End the call and contact the service through its official support channel.",
            "Do not install remote-control software or share your screen for an unsolicited caller.",
        ],
    },
)


def get_scenario(scenario_id):
    return next((scenario for scenario in SCENARIOS if scenario["id"] == scenario_id), None)
