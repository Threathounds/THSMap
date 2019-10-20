echo "Use this token: $(python3 thsdashboard/token.py | cut -f 2 -d ' ')"
python3 manage.py runserver
