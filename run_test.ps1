param($ScriptPath = "C:\Users\Sachit Sharma\Documents\DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning\test_bidirectional_fixed.py")

cd /d "C:\Users\Sachit Sharma\Documents\DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning"

python -c "exec(open('$ScriptPath').read().replace(\"C:\", \"c:\"))"