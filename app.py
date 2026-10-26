#Web version of PhishGuard using Flask
#Run this with: python app.py
#Then open http://127.0.0.1:5000 in your browser

from flask import Flask, render_template, request
from detector import is_suspicious_url

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    #POST means the user submitted the form (clicked the button)
    if request.method == "POST":
        user_url = request.form["url"]
        score, verdict, reasons = is_suspicious_url(user_url)
        result = {
            "url": user_url,
            "score": score,
            "verdict": verdict,
            "reasons": reasons,
        }

    #Show the page, passing in the result (or None if nothing submitted yet)
    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)