from flask import Flask, render_template, request
from recon import recon_data  # we’ll modify your code

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        domain = request.form.get("domain")
        result = recon_data(domain)

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)