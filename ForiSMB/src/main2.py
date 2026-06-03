import subprocess
import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

scripts = [
    "build_dataset.py",
    "hybrid_risk_pipeline_final.py",
    "xai_explanations.py"
]

def run_script(script):
    script_path = os.path.join(BASE_DIR, script)

    if not os.path.exists(script_path):
        print(f"\n❌ Script not found: {script_path}")
        sys.exit(1)

    print("\n" + "=" * 70)
    print(f"Running: {script}")
    print("=" * 70)

    result = subprocess.run([sys.executable, script_path])

    if result.returncode != 0:
        print(f"\n❌ Error running {script}")
        sys.exit(result.returncode)

    print(f"✅ Finished: {script}")

def main():
    print("\n🚀 Starting FortiSMB Insider Threat Detection Pipeline\n")
    print("Pipeline order:")
    print("1. Build unified dataset")
    print("2. Run hybrid risk pipeline")
    print("3. Run XAI explanations\n")

    for script in scripts:
        run_script(script)

    print("\n🎉 Pipeline completed successfully!")

if __name__ == "__main__":
    main()