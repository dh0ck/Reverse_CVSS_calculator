# Reverse_CVSS_calculator
Enter a CVSS value and discover the possible combinations that produce that value

## Usage
```python3
python3 reverse_cvss.py  # Enter interactively the target CVSS score and the number of desired results
python3 reverse_cvss.py 3.4  # You will be asked how many results you want (leave empty and press enter to get 20 results
python3 reverse_cvss.py 3.4 15  # Produces 15 combinations of CVSS vectors that have a 3.4 CVSS score
python3 reverse_cvss.py -h # help menu
python3 reverse-cvss.py help # help menu
```

At the moment, only CVSS v2 is supported, v3 will be added soon
