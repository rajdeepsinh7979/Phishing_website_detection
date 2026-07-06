from flask import Flask, render_template, request
import joblib

app = Flask(__name__)

# Load trained model
model = joblib.load("stacking_model.pkl")

FEATURE_GROUPS = {
    "URL Features": [
        "having_IP_Address",
        "URL_Length",
        "Shortining_Service",
        "having_At_Symbol",
        "double_slash_redirecting",
        "Prefix_Suffix",
        "having_Sub_Domain"
    ],

    "Security Features": [
        "SSLfinal_State",
        "HTTPS_token",
        "port",
        "Domain_registeration_length",
        "DNSRecord",
        "age_of_domain"
    ],

    "Content Features": [
        "Request_URL",
        "URL_of_Anchor",
        "Links_in_tags",
        "SFH",
        "Submitting_to_email",
        "Abnormal_URL",
        "Iframe"
    ],

    "Behaviour Features": [
        "Redirect",
        "on_mouseover",
        "RightClick",
        "popUpWidnow"
    ],

    "Popularity Features": [
        "web_traffic",
        "Page_Rank",
        "Google_Index",
        "Links_pointing_to_page",
        "Statistical_report",
        "Favicon"
    ]
}

FEATURE_LABELS = {
    "having_IP_Address":"IP Address in URL",
    "URL_Length":"URL Length",
    "Shortining_Service":"Shortened URL",
    "having_At_Symbol":"Contains @ Symbol",
    "double_slash_redirecting":"Double Slash Redirect",
    "Prefix_Suffix":"Hyphen in Domain",
    "having_Sub_Domain":"Subdomain Count",
    "SSLfinal_State":"SSL Certificate",
    "Domain_registeration_length":"Domain Registration Length",
    "Favicon":"External Favicon",
    "port":"Non-standard Port",
    "HTTPS_token":"HTTPS Token in Domain",
    "Request_URL":"External Resource Requests",
    "URL_of_Anchor":"Anchor URL Status",
    "Links_in_tags":"Links in HTML Tags",
    "SFH":"Server Form Handler",
    "Submitting_to_email":"Form Submission to Email",
    "Abnormal_URL":"Abnormal URL",
    "Redirect":"Redirect Count",
    "on_mouseover":"Mouse Hover Script",
    "RightClick":"Right Click Disabled",
    "popUpWidnow":"Popup Window",
    "Iframe":"Uses iFrame",
    "age_of_domain":"Domain Age",
    "DNSRecord":"DNS Record",
    "web_traffic":"Website Traffic",
    "Page_Rank":"Page Rank",
    "Google_Index":"Google Indexed",
    "Links_pointing_to_page":"Backlinks",
    "Statistical_report":"Blacklist Report"
}

FEATURE_OPTIONS = {

    "having_IP_Address": [
        (-1, "Uses IP Address"),
        (1, "Uses Domain Name")
    ],

    "URL_Length": [
        (-1, "Long URL"),
        (0, "Medium URL"),
        (1, "Short URL")
    ],

    "Shortining_Service": [
        (-1, "Shortened URL"),
        (1, "Normal URL")
    ],

    "having_At_Symbol": [
        (-1, "Contains @ Symbol"),
        (1, "No @ Symbol")
    ],

    "double_slash_redirecting": [
        (-1, "Contains // Redirect"),
        (1, "No // Redirect")
    ],

    "Prefix_Suffix": [
        (-1, "Contains Hyphen"),
        (1, "No Hyphen")
    ],

    "having_Sub_Domain": [
        (-1, "Many Subdomains"),
        (0, "Moderate"),
        (1, "Few / None")
    ],

    "SSLfinal_State": [
        (-1, "No SSL"),
        (0, "Suspicious SSL"),
        (1, "Valid SSL")
    ],

    "Domain_registeration_length": [
        (-1, "Short Registration"),
        (1, "Long Registration")
    ],

    "Favicon": [
        (-1, "External Favicon"),
        (1, "Internal Favicon")
    ],

    "port": [
        (-1, "Non-standard Port"),
        (1, "Standard Port")
    ],

    "HTTPS_token": [
        (-1, "Contains HTTPS Token"),
        (1, "No HTTPS Token")
    ],

    "Request_URL": [
        (-1, "Mostly External"),
        (0, "Mixed"),
        (1, "Mostly Internal")
    ],

    "URL_of_Anchor": [
        (-1, "Unsafe"),
        (0, "Suspicious"),
        (1, "Safe")
    ],

    "Links_in_tags": [
        (-1, "Mostly External"),
        (0, "Mixed"),
        (1, "Mostly Internal")
    ],

    "SFH": [
        (-1, "Blank"),
        (0, "Suspicious"),
        (1, "Valid")
    ],

    "Submitting_to_email": [
        (-1, "Submits to Email"),
        (1, "Normal Submission")
    ],

    "Abnormal_URL": [
        (-1, "Abnormal"),
        (1, "Normal")
    ],

    "Redirect": [
        (0, "No Redirect"),
        (1, "One Redirect"),
        (-1, "Multiple Redirects")
    ],

    "on_mouseover": [
        (-1, "Changes Status Bar"),
        (1, "Normal")
    ],

    "RightClick": [
        (-1, "Disabled"),
        (1, "Enabled")
    ],

    "popUpWidnow": [
        (-1, "Popup Present"),
        (1, "No Popup")
    ],

    "Iframe": [
        (-1, "Uses iFrame"),
        (1, "No iFrame")
    ],

    "age_of_domain": [
        (-1, "New Domain"),
        (1, "Old Domain")
    ],

    "DNSRecord": [
        (-1, "Missing"),
        (1, "Exists")
    ],

    "web_traffic": [
        (-1, "Low"),
        (0, "Medium"),
        (1, "High")
    ],

    "Page_Rank": [
        (-1, "Low"),
        (0, "Medium"),
        (1, "High")
    ],

    "Google_Index": [
        (-1, "Not Indexed"),
        (1, "Indexed")
    ],

    "Links_pointing_to_page": [
        (-1, "Few"),
        (0, "Moderate"),
        (1, "Many")
    ],

    "Statistical_report": [
        (-1, "Blacklisted"),
        (1, "Clean")
    ]
}

@app.route("/")
def home():
    return render_template(
    "index.html",
    feature_groups=FEATURE_GROUPS,
    feature_labels=FEATURE_LABELS,
    feature_options=FEATURE_OPTIONS
)


@app.route("/predict", methods=["POST"])
def predict():

    values = []

    for group in FEATURE_GROUPS.values():
        for feature in group:
            values.append(int(request.form.get(feature)))

    prediction = model.predict([values])[0]

    confidence = None

    if hasattr(model, "predict_proba"):
        confidence = round(max(model.predict_proba([values])[0]) * 100, 2)

    # Change this if your labels are reversed
    if prediction == 1:
        result = "Legitimate Website"
        recommendation = "This website appears to be legitimate based on the selected features."
    else:
        result = "Phishing Website"
        recommendation = "Do NOT trust this website. It exhibits characteristics commonly associated with phishing websites."

    return render_template(
    "result.html",
    result=result,
    confidence=confidence,
    recommendation=recommendation,
    prediction=prediction
)


if __name__ == "__main__":
    app.run(debug=True)