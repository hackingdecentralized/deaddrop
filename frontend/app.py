import json
from flask import Flask, render_template, request, redirect, url_for, flash
from models import db, Entry, BugReport
from datetime import datetime

app = Flask(__name__)
app.config.update({
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///data.db',
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SECRET_KEY': 'replace-with-a-secure-random-value',
})
db.init_app(app)

with app.app_context():
    db.create_all()

# Show list at the root URL
@app.route('/', methods=['GET'])
def show_list():
    entries = Entry.query.order_by(Entry.timestamp.desc()).all()
    return render_template('list.html', entries=entries, current_year=datetime.utcnow().year)

# New “register” page for adding entries
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        e = Entry(
            pk_clue=request.form['pk_clue'],
            pk_encryption=request.form['pk_encryption'],
            sc_addr=request.form['sc_addr'],
            constraints=request.form['constraints']
        )
        db.session.add(e)
        db.session.commit()
        flash("Entry saved!", "success")
        return redirect(url_for('show_list'))
    return render_template('register.html', current_year=datetime.utcnow().year)

@app.route('/submit_bug', methods=['GET', 'POST'])
def submit_bug():
    if request.method == 'POST':
        file = request.files.get('bugfile')
        if not file or not file.filename.lower().endswith('.json'):
            flash("Please upload a .json file", "danger")
        else:
            try:
                data = json.load(file)
            except ValueError:
                flash("Invalid JSON!", "danger")
            else:
                # ensure all required keys are present
                required = ['bugid', 'ciphertext', 'omr_payload', 'omr_clue', 'attestation']
                if not all(k in data for k in required):
                    flash("JSON must include keys: " + ", ".join(required), "danger")
                else:
                    bug = BugReport(
                        bugid      = data['bugid'],
                        ciphertext = data['ciphertext'],
                        omr_payload= json.dumps(data['omr_payload']),
                        omr_clue   = data['omr_clue'],
                        attestation= data['attestation'],
                    )
                    db.session.add(bug)
                    db.session.commit()
                    flash("Bug report submitted!", "success")
                    return redirect(url_for('show_list'))

    # example JSON to display
    example_json = {
      "bugid": "BR-1234",
      "ciphertext": "0xdeadbeef…",
      "omr_payload": {"foo": 1, "bar": 2},
      "omr_clue": "some-clue",
      "attestation": "signed-by-x509…"
    }

    return render_template(
        'submit_bug.html',
        example_json=example_json,
        current_year=datetime.utcnow().year
    )

@app.route('/bug_lookup', methods=['GET', 'POST'])
def bug_lookup():
    bugs = None
    pk_detect = ""
    bug_id = ""
    tool_error = None

    if request.method == 'POST':
        form_type = request.form.get('form_type')

        if form_type == "detect_lookup":
            pk_detect = request.form.get('pk_detect', '').strip()

            if pk_detect == "*":
                bugs = BugReport.query.order_by(BugReport.timestamp.desc()).all()
            elif pk_detect:
                import os
                filepath = os.path.abspath("/tmp/omr_data.json")
                detector_path = os.getenv("DETECTOR_PATH", None)
                if not detector_path:
                    raise Exception("detector path env not set")
                reports = BugReport.query.all()
                omr_list = [
                    {
                        "clue": report.omr_clue,
                        "payload": report.omr_payload
                    }
                    for report in reports
                    if report.omr_clue and report.omr_payload
                ]

                data = { "omr": omr_list }

                with open(filepath, "w") as f:
                    json.dump(data, f, indent=2)

                print(f"✅ Exported {len(omr_list)} entries to {filepath}")

                try:
                    import subprocess
                    cmd = [detector_path, pk_detect, filepath]
                    print("🔧 Running command:", " ".join(cmd))

                    result = subprocess.run(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True,
                        text=True
                    )
                    raw_bugs = json.loads(result.stdout)
                    bugs = []
                    for b in raw_bugs:
                        bugs.append({
                            "bugid": b.get("bugid"),
                            "ciphertext": b.get("decryption_key"),
                            "timestamp": datetime.fromisoformat(b.get("timestamp"))
                        })
                except FileNotFoundError:
                    tool_error = "❌ detect_tool not found. Please make sure it is compiled and located in the project directory."
                except subprocess.CalledProcessError as e:
                    tool_error = f"❌ detect_tool failed with exit code {e.returncode}: {e.stderr.strip()}"
                except json.JSONDecodeError as e:
                    tool_error = f"❌ Failed to parse JSON output from tool: {e}"
                print(tool_error)

    return render_template("bug_lookup.html",
                           pk_detect=pk_detect,
                           bug_id=bug_id,
                           bugs=bugs,
                           tool_error=tool_error,
                           current_year=datetime.utcnow().year)


@app.route('/bug_reports')
def all_bug_reports():
    all_bugs = BugReport.query.order_by(BugReport.timestamp.desc()).all()
    return render_template("all_bug_reports.html", bugs=all_bugs)