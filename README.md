# FortiSMB

RBAC-Enhanced Insider Threat Detection using Isolation Forest.

## How to Run

python -m venv venv  
source venv/Scripts/activate  
pip install -r requirements.txt  

python src/check_users.py  
python src/build_dataset.py  
python src/train_iforest.py  

## Dataset
This project uses the CERT Insider Threat dataset (Kaggle).
Due to size and licensing, the dataset files are not stored in this GitHub repository.

Place these files locally in `data/raw/`:
- users.csv
- logon.csv
- device.csv
- file.csv

