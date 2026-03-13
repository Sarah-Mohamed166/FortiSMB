import subprocess
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

scripts = [
    "build_dataset.py",
    "isolation_forest_model_+_its_metrics.py",
    "generate_scores.py",
    "risk_classification.py",
    "xai_explanations.py"
]

def run_script(script):
    script_path = os.path.join(BASE_DIR, script)

    print("\n" + "=" * 60)
    print(f"Running: {script}")
    print("=" * 60)

    result = subprocess.run([sys.executable, script_path])

    if result.returncode != 0:
        print(f"\n❌ Error running {script}")
        sys.exit(result.returncode)

    print(f"✅ Finished: {script}")

def main():
    print("\n🚀 Starting FortiSMB Insider Threat Detection Pipeline\n")

    for script in scripts:
        run_script(script)

    print("\n🎉 Pipeline completed successfully!")

if __name__ == "__main__":
    main()