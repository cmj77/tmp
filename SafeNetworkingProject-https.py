from flask import Flask
from flask_googlecharts import LineChart
from flask_googlecharts import GoogleCharts, BarChart, MaterialLineChart
from flask_googlecharts.utils import prep_data
import datetime
import os
import csv
from io import StringIO
from flask import Flask, render_template, redirect, flash, url_for, request, session, abort, jsonify
from jinja2 import Template
from flask import send_from_directory
import psycopg2
from flask import Flask, jsonify
from flask import abort
from flask import request
from flask import Flask, make_response
from flask import Flask, Response
import pygal
from pygal import Config
from pygal.style import CleanStyle
from pygal.style import DarkStyle
from werkzeug.utils import secure_filename
from OpenSSL import SSL
import flask_googlecharts
from jinja2 import Environment, FileSystemLoader
import flask
import urllib
from flask_wtf import Form
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired
from wtforms.fields.html5 import DateField
import json
from types import *
JSON_HOST = "http://localhost:8001"
app = Flask(__name__)
#charts = GoogleCharts(app)
#charts.init_app(app)

class ExampleForm(Form):
    dt = DateField('DatePicker', format='%Y-%m-%d')

@app.route('/login', methods=['POST'])
def do_admin_login():
        if request.form['username'] == 'admin' and  request.form['password'] == 'SafeNetworking123!':
            session['logged_in'] = True 
        else:
            flash('Invalid Credentials')
        return template_test()

@app.route("/")
@app.route("/<int:page>")
def template_test(page=1):
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        offset = (page-1) * 100 # 50 is the page size
        if offset < 0:
            offset = 0
        conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
        cur = conn.cursor()
        cur.execute('''
         Select connectionreport2."Time Logged", connectionreport2."Source address", connectionreport2."Destination address", connectionreport2."Threat/Content Name", connectionreport2."tags", connectionreport2."tagurl", connectionreport2."lookup", connectionreport2."dstlookup" from connectionreport2 ''')
    rows = cur.fetchall();
    form = ExampleForm()
    if form.validate_on_submit():
        print(form.dt.data)
        newdata = form.dt.data
        cur.execute('''
            SELECT connectionreport2."Time Logged", connectionreport2."Source address", connectionreport2."Destination address", connectionreport2."Threat/Content Name", connectionreport2."tags", connectionreport2."tagurl", connectionreport2."lookup", connectionreport2."dstlookup" FROM connectionreport2 WHERE CAST(connectionreport2."Time Logged" as DATE) = '{}' '''.format(newdata))
        rows = cur.fetchall();
        print(rows)
        print(newdata)
        return render_template("index.html", form=form, rows=rows, page=page)
    conn.close()
    return render_template("index.html", rows=rows, form=form)

#            Select * from connectionreport where tag != '' ''')
#        rows = cur.fetchall();
#        print(rows)
#        return render_template('index.html', name=template_test, rows=rows, page=page)

@app.route("/logout")
def logout():
    session['logged_in'] = False
    return template_test()

@app.route('/newmenu/')
def newmenu():
    return render_template('newmenu.html')

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = set(['csv'])

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/importcsv', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('uploaded_file',
                                    filename=filename))
    return '''
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Safe Networking Palo Alto Networks - FileType</title>
<link rel="shortcut icon" type="image/x-icon" href="/static/pan-logo-badge-green-dark-kick-up.png" />
<!-- Bootstrap -->
<link rel="stylesheet" href="/static/css/bootstrap.css">

<!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
<!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
<!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
</head>
<body>
<!-- HEADER -->
<header>
    <div class="container">
      <div class="row">
        <div class="col-xs-12">
          <h1 class="text-center"><a href="/"><img src="/static/pan-logo-badge-green-dark-kick-up.png" alt="" width="250" height="180" class="img-thumbnail img-responsive" align="left"/></a></h1>
  <h1 class="text-center"><font color=#463E3F>S</font><font color=#2B60DE>a</font><font color=#4AA02C>f</font><font color=#82CAFF>e</font> <font color=#E8A317>N</font><font color=#9F000F>e</font><font color=#463E3F>t</font><font color=#2B60DE>w</font><font color=#4AA02C>o</font><font color=#82CAFF>r</font><font color=#E8A317>k</font><font color=#9F000F>i</font><font color=#2B60DE6>n</font><font color=#2B60DE>g</font> </h1>
          <h2 class="text-center"><em> Service Provider Solutions</em></h2>
          <right></right>
        </div>
      </div>
    </div>
<em><h2>
 <n class="label label-default"><a href="/" style="color:white">Home</a></span> <span class="label label-primary"><a href="/funnel" style="color:white">Malicious File Types Linked to Domain</a></span> <span class="label label-success"><a href="/srchits" style="color:white">Source IP Events Generated</a></span> <span class="label label-info"><a href="/srcipreport/1" style="color:white" >Source IP with Threat & Malware Category</a></span> <span class="label label-warning"><a href="/malwarefamily" style="color:white">Malware Categories</a></span> <span class="label label-danger" style="color:white">Administration</span>  <span class="label label-default" style="color:white"><a href="/importcsv" style="color:white" >Import CSV Threat Feed</a></span> <span class="label label-primary"><a href="/domainmalicioussamples" style="color:white">Per Domain Malicious Sample File Type Count</a></span>  <span class="label label-default"><a href="/logout" style="color:white">Log Out</a></span></em></h2>

    <head>
        <style>
           table {border-collapse:collapse; table-layout:fixed; width:1220px;}
           table td {border:solid 2px #fab; width:100px; word-wrap:break-word;}
        </style>
    </head>

 <body>
<br>
    <title>Upload CSV File</title>
    <h1>Upload File</h1>
    <form method=post enctype=multipart/form-data>
      <p><input type=file name=file>
         <input type=submit value=Upload>
    </form>
    </body>
</html>
      '''

@app.route('/configuration', methods=['GET'])
def configuration():
    with open('config.json') as data:
        json_data = json.load(data)
        custkey = json_data["autofocus"]["apiKey"]
    return render_template('configuration.html', custkey=custkey)

@app.route('/configkey', methods=['POST'])
def configkey():
    lici = request.form.to_dict()
    lic = request.form["lic"]
    
    if request.method == 'POST':

        print(request.form)
        print(lic)
        print("%s" % lic)

        with open('config1.json') as infile, open('config.json', 'w') as outfile:
            for line in infile:
                for src, target in lici.items():
                    line = line.replace(src, target)
                outfile.write(line)

        return redirect('/configuration')
    return render_template('configuration.html')

@app.route('/configurationW', methods=['GET'])
def configurationW():
    with open('configwhois.json') as data:
        json_data = json.load(data)
        iplookup = json_data["registry"]["whoislookup"]
    return render_template('configurationW.html', iplookup=iplookup)


@app.route('/configwhois', methods=['POST'])
def configwhois():
    whoislookup = request.form.to_dict()
    lkup = request.form["lkup"]

    if request.method == 'POST':

        print(request.form)
        print(lkup)
        print("%s" % lkup)

        with open('config1whois.json') as infile, open('configwhois.json', 'w') as outfile:
            for line in infile:
                for src, target in whoislookup.items():
                    line = line.replace(src, target)
                outfile.write(line)

        return redirect('/configurationW')
    return render_template('configurationW.html')


@app.route('/list')
def list():

    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')

    cur = conn.cursor()
    cur.execute('''SELECT "Source address", "Destination address", "Time Logged", "ThreatType", "Threat/Content Name", "Severity", "Destination Country" FROM sn1dnsthreatnameraw LIMIT 100''')
    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("list.html", rows=rows)

@app.route('/android')
def androidreport():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    t = ('Android APK',)
    cur = conn.cursor()
    cur.execute('SELECT create_date, filetype, domain, md5, size FROM afqsn WHERE filetype =?', t)
    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("android.html", rows=rows)


@app.route('/botnet')
def botreport():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
    cur.execute('SELECT * FROM sn1dnsthreatnameraw WHERE "Destination Port" <> "53"')
    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("botnet.html", rows=rows)


@app.route('/srchits')
def srchits():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
    cur.execute('''select "Source address", count("Source address") from sn1dnseventsraw group by "Source address" ORDER BY 2 DESC''')
    rows = cur.fetchall();
    print(rows)
    conn.close()
    return render_template("n-srcipintell.html", rows=rows)

@app.route('/threattype')
def threattype():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')

    cur = conn.cursor()
    cur.execute('''select "Threat/Content Name", count("Threat/Content Name") from sn1dnseventsraw group by "Threat/Content Name" ORDER BY 2 DESC''')
    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("threattype.html", rows=rows)

@app.route('/badlist')
def badlist():
    return render_template("Bad_List.txt")

@app.route('/srcipreport', methods=['GET', 'POST'])
@app.route('/srcipreport/<int:page>')
def srcipreport_paginated(page=1):
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
    offset = (page-1) * 100 # 50 is the page size
    if offset < 0:
      offset = 0
    cur.execute('''
         Select * from connectionreport''')
    rows = cur.fetchall();
    form = ExampleForm()
    if form.validate_on_submit():
        print(form.dt.data)
        newdata = form.dt.data
        cur.execute('''
            SELECT connectionreport."Time Logged", connectionreport."Source address", connectionreport."Destination address", connectionreport."Threat/Content Name", connectionreport."tag" from connectionreport WHERE CAST(connectionreport."Time Logged" as DATE) = '{}' '''.format(newdata))          

#SELECT Distinct connectionreport."Time Logged", connectionreport."Source address", connectionreport."Destination address", connectionreport."Threat/Content Name", connectionreport."URL", afqsn.tags FROM connectionreport inner join afqsn on connectionreport."URL" = afqsn.domain or connectionreport."Threat/Content Name" = afqsn.domain WHERE CAST(connectionreport."Time Logged" as DATE) = '{}' and afqsn.tag != '' '''.format(newdata)) 
# Select * from connectionreport WHERE CAST(connectionreport."Time Logged" as DATE) = '{}' and tag != '' '''.format(newdata))
#         SELECT Distinct sn1dnsthreatnameraw."Source address", sn1dnsthreatnameraw."ThreatType", afqsn.tag, sn1dnsthreatnameraw."Threat/Content Name", sn1dnsthreatnameraw."Time Logged" FROM sn1dnsthreatnameraw inner join afqsn on sn1dnsthreatnameraw."Threat/Content Name" = afqsn.domain WHERE CAST(sn1dnsthreatnameraw."Time Logged" as DATE) = '{}' and afqsn.tag != '' '''.format(newdata))
        rows = cur.fetchall();
        print(rows)
        print(newdata)
        return render_template("autofocusintel.html", form=form, rows=rows, page=page)
    print()
    conn.close()
    return render_template("autofocusintel.html", rows=rows, form=form, page=page)

@app.route('/pertag', methods=['GET', 'POST'])
def pertag():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
    cur.execute('''
         Select connectionreport2."Time Logged", connectionreport2."Source address", connectionreport2."Destination address", connectionreport2."Threat/Content Name", connectionreport2."tags", connectionreport2."tagurl" from connectionreport2 ''')
    rows = cur.fetchall();
    form = ExampleForm()
    if form.validate_on_submit():
        print(form.dt.data)
        newdata = form.dt.data
        cur.execute('''
            SELECT connectionreport2."Time Logged", connectionreport2."Source address", connectionreport2."Destination address", connectionreport2."Threat/Content Name", connectionreport2."tags", connectionreport2."tagurl" FROM connectionreport2 WHERE CAST(connectionreport2."Time Logged" as DATE) = '{}' '''.format(newdata))
        rows = cur.fetchall();
        print(rows)
        print(newdata)
        return render_template("index.html", form=form, rows=rows, page=page)
    conn.close()    
    return render_template("index.html", rows=rows, form=form)

@app.route('/mergedtag', methods=['GET', 'POST'])
def mergedtag():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
    cur.execute('''
         Select * from connectionreport where tag != '' ''')
    rows = cur.fetchall();
    form = ExampleForm()
    if form.validate_on_submit():
        print(form.dt.data)
        newdata = form.dt.data
        cur.execute('''
            SELECT connectionreport."Time Logged", connectionreport."Source address", connectionreport."Destination address", connectionreport."Threat/Content Name" FROM connectionreport WHERE CAST(connectionreport."Time Logged" as DATE) = '{}' '''.format(newdata))
        rows = cur.fetchall();
        print(rows)
        print(newdata)
        return render_template("index.html", form=form, rows=rows, page=page)
    conn.close()

    return render_template("index.html", rows=rows, form=form)

@app.route('/emptytag', methods=['GET', 'POST'])
def emptytag():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
    cur.execute('''
         Select * from connectionreport ''')
    rows = cur.fetchall();
    form = ExampleForm()
    if form.validate_on_submit():
        print(form.dt.data)
        newdata = form.dt.data
        cur.execute('''
            SELECT connectionreport."Time Logged", connectionreport."Source address", connectionreport."Destination address", connectionreport."Threat/Content Name" FROM connectionreport WHERE CAST(connectionreport."Time Logged" as DATE) = '{}' '''.format(newdata))
        rows = cur.fetchall();
        print(rows)
        print(newdata)
        return render_template("index.html", form=form, rows=rows, page=page)
    conn.close()

    return render_template("index.html", rows=rows)

@app.route('/dashboard')
def dashboard():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
#Top Severity Distribution
    cur.execute('''
    SELECT "Severity", count(*) as count from sn1dnseventsraw group by "Severity"
    ''')
    rows = cur.fetchall()
    print(rows)

    chart = pygal.Pie()
    pie_chart = pygal.Pie(width=300,height=300,truncate_legend=-1)

    pie_chart.title = 'Alert Severity Distribution'
    for row in rows:
        print (row)
        pie_chart.add('%s: %s' % (row[0], row[1]), [{'value': row[1], 'label': row[0]}])
    chart = pie_chart.render(is_unicode=True)
#Top 5 Domain Report
    cur.execute('''
        SELECT "Threat/Content Name", count(*) as count from sn1dnsthreatnameraw where "Threat/Content Name" != '' and "Threat/Content Name" != '""' group by "Threat/Content Name" order by count desc limit 10
    ''')
    rows1 = cur.fetchall()
    print(rows1)
    chart1 = pygal.HorizontalBar(rounded_bars=2)
    bar_chart = pygal.HorizontalBar(width=300,height=300,truncate_legend=-1)
    bar_chart.title = 'Top 10 Domains'
# (in %)'
    for row1 in rows1:
        print (rows1)
        bar_chart.add('%s: %s' % (row1[0], row1[1]), [{'value': row1[1],  'label': row1[0]}])
    chart1 = bar_chart.render(is_unicode=True)

#Top Threat Category
    cur.execute('''
    SELECT "Threat/Content Type", count(*) as count from sn1dnseventsraw group by "Threat/Content Type" order by count desc limit 4
    ''')
    rows2 = cur.fetchall()

    chart2 = pygal.HorizontalBar(rounded_bars=20)
    bar_chart = pygal.HorizontalBar(width=300,height=300,truncate_legend=-1)
    bar_chart.title = 'Top Threat Categories'
# (in %)'
    for row2 in rows2:
        print (rows2)
        bar_chart.add('%s: %s' % (row2[0], row2[1]), [{'value': row2[1], 'label':str(row2[0])}])
    chart2 = bar_chart.render(is_unicode=True)

#Infected Source IP
    cur.execute('''
    SELECT count(distinct "Source address") as count from sn1dnseventsraw
    ''')
    rows12 = cur.fetchall()
    print(int(rows12[0][0]))
    infected = int(rows12[0][0])
    print (infected)
    for row12 in rows12:
        print (str(rows12))
    chart12 = pygal.SolidGauge(half_pie=True, inner_radius=0.80, human_readable = True, style=pygal.style.styles['default'](value_font_size=25,value_label_font_size=25,title_font_size=25,label_font_size=25,legend_font_size=25))
    percent_formatter = lambda x: '{:.30g} Source IPs'.format(x)
    dollar_formatter = lambda x: '{:.10g}$'.format(x)
    chart12.value_formatter = percent_formatter
    chart12.add('Possible Infections', [{'value': infected, 'color': 'red','max_value': 1000000}])
    chart12 = chart12.render(is_unicode=True)



#Top Source IP    

    cur.execute('''
    SELECT "Source address", count(*) as count from sn1dnseventsraw group by "Source address" order by count desc limit 10
    ''')
    rows5 = cur.fetchall()

    chart5 = pygal.HorizontalBar(rounded_bars=2)
    bar_chart = pygal.HorizontalBar(width=300,height=300,truncate_legend=-1)
    bar_chart.title = 'Top 10 Source IP Addresses'
# (in %)'
    for row5 in rows5:
        print (rows5)
        bar_chart.add('%s: %s' % (row5[0], row5[1]), [{'value': row5[1], 'label': row5[0]}])
    chart5 = bar_chart.render(is_unicode=True)

#Top Dest IP    

    cur.execute('''
    SELECT "Destination address", count(*) as count from sn1dnseventsraw group by "Destination address" order by count desc limit 10
    ''')
    rows6 = cur.fetchall()

    chart6 = pygal.HorizontalBar(rounded_bars=2)
    bar_chart = pygal.HorizontalBar(width=300,height=300,truncate_legend=-1)
    bar_chart.title = 'Top 10 Destination Addresses'
# (in %)'
    for row6 in rows6:
        print (rows6)
        bar_chart.add('%s: %s' % (row6[0], row6[1]), [{'value': row6[1], 'label': row6[0]}])
    chart6 = bar_chart.render(is_unicode=True)

 
#Top Malware Families

    cur.execute('''
    SELECT "tags", count(*) as count from connectionreport2 where "tags" != '' group by "tags" order by count desc limit 10
    ''')
    rows3 = cur.fetchall()

    chart3 = pygal.HorizontalBar(rounded_bars=20, style=CleanStyle)
    bar_chart = pygal.HorizontalBar(width=300,height=300,truncate_legend=-1)
    bar_chart.title = 'Top Malware Families'
# (in %)'
    for row3 in rows3:
        print (rows3)
        bar_chart.add('%s: %s' % (row3[0], row3[1]), [{'value': row3[1], 'label': row3[0]}])
    chart3 = bar_chart.render(is_unicode=True)

   
#Total Domains

    cur.execute('''
    SELECT "domain", count(*) as count from snuniquedomains group by "domain" order by count desc limit 10''')
    rows7 = cur.fetchall()

    chart7 = pygal.HorizontalBar(rounded_bars=20, style=CleanStyle)
    bar_chart = pygal.HorizontalBar(width=300,height=300,truncate_legend=-1)
    bar_chart.title = 'Domain Count'
# (in %)'
    for row7 in rows7:
        print (rows7)
        bar_chart.add('%s: %s' % (row7[0], row7[1]), [{'value': row7[1], 'label': row7[0]}])
    chart7 = bar_chart.render(is_unicode=True)

    return render_template('dashboard.html', chart=chart, chart2=chart2, chart3=chart3, chart1=chart1, chart5=chart5, chart6=chart6, chart7=chart7, chart12=chart12)

 


@app.route('/top5dom')
def top5dom():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()

    cur.execute('''
    SELECT "Threat/Content Name","URL", count(*) as count from sn1dnsthreatnameraw group by "Threat/Content Name", "URL", order by count desc limit 5
    ''')
    rows4 = cur.fetchall()

    chart4 = pygal.HorizontalBar(rounded_bars=2)
    bar_chart = pygal.HorizontalBar(width=300,height=300,truncate_legend=-1)
    bar_chart.title = 'Top 5 Domains'
# (in %)'
    for row4 in rows4:   
        print (rows4)
        bar_chart.add('%s: %s' % (row4[0], row4[1]), [{'value': row4[1], 'label': row4[0]}])
    chart4 = bar_chart.render(is_unicode=True)    
    return render_template('dashboardt5.html', chart4=chart4)

@app.route('/rounded')
def rounded():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()

    cur.execute('''
    SELECT "thr_category", count(*) as count from sn1rawlogs group by "thr_category" order by count desc limit 4
    ''')
    rows = cur.fetchall()

    chart = pygal.Bar(rounded_bars=20)
    bar_chart = pygal.Bar(width=300,height=300,truncate_legend=-1)
    bar_chart.title = 'Top Threat Categories'
    for row in rows:
        print (rows)
        bar_chart.add('%s: %s' % (row[0], row[1]), [{'value': row[1], 'label': row[0]}])
    chart = bar_chart.render(is_unicode=True)
    return render_template('dashboardt5.html', chart=chart)



@app.route('/chart1')
def test():
    bar_chart = pygal.HorizontalStackedBar()
    bar_chart.title = "Remarquable sequences"
    bar_chart.x_labels = map(str, range(11))
    bar_chart.add('Fibonacci', [0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55])
    bar_chart.add('Padovan', [1, 1, 1, 2, 2, 3, 4, 5, 7, 9, 12])
    chart = bar_chart.render(is_unicode=True)
    return render_template('chart.html', chart=chart)

@app.route("/searchtest")
def searchtest():
    """Simple search for terms, with optional limit and paging"""
    query = flask.request.args.get('query', '')
    page = flask.request.args.get('page', '')
    jsonu = u"%s/searchtest/%s/" % (JSON_HOST, urllib.parse.quote_plus(query.encode('utf-8')))
    print(jsonu)
    if page:
        jsonu = u"%s%d" % (jsonu, int(page))
    res = json.loads(urllib.request.urlopen(jsonu).read().decode('utf-8'))
    template = env.get_template('resultstest.html')
    return(template.render(
        terms=res['query'].replace('+', ' '),
        results=res,
        request=flask.request
    ))


@app.route('/searching', methods=['GET', 'POST'])
def searching():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
    cur.execute('''
        SELECT sn1dnsthreatname."Source address", sn1dnsthreatname."ThreatType", afqsn.tag, sn1dnsthreatname."Threat/Content Name", sn1dnsthreatname."Time Logged" FROM sn1dnsthreatname inner join afqsn on sn1dnsthreatname."Threat/Content Name" = afqsn.domain''')
    rows = cur.fetchall(); 
    return render_template('searching.html', rows=rows)



@app.route('/searchip', methods=['GET', 'POST'])
def searchip():
    if request.method == "GET":
        try:
            search_item = request.args.get('search_item')
            conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
            cur = conn.cursor()
            print (search_item)
            cur.execute('''select * from connectionreport WHERE "Source address" = '{}' '''.format(search_item))
            rows=cur.fetchall()
            print (str(type(rows)))
            return render_template('resultsip.html', rows=rows)
        except OSError: 
            return "err "
        else:
            return "sql err"
    return render_template('searchip.html')

@app.route('/searchdestip', methods=['GET', 'POST'])
def searchdestip():
    if request.method == "GET":
        try:
            search_item = request.args.get('search_item')
            conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
            cur = conn.cursor()
            print (search_item)
            cur.execute('''select * from connectionreport WHERE "Destination address" = '{}' '''.format(search_item))
            rows=cur.fetchall()
            print (str(type(rows)))
            return render_template('resultsdestip.html', rows=rows)
        except OSError:
            return "err "
        else:
            return "sql err"
    return render_template('searchdestip.html')


@app.route('/searchmalwarecat', methods=['GET', 'POST'])
def searchmalware():
    if request.method == "GET":
        try:
            search_item = request.args.get('search_item')
            conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
            cur = conn.cursor()
            print (search_item)
            cur.execute('''select * from connectionreport WHERE "tag" = '{}' '''.format(search_item))
            rows=cur.fetchall()
            print (str(type(rows)))
            return render_template('resultsmalwarecat.html', rows=rows)
        except OSError:
            return "err "
        else:
            return "sql err"
    return render_template('searchmalwarecat.html')

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == "GET":
        try:
            search_item = request.args.get('search_item')
            conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
            cur = conn.cursor()
            print (search_item)
            cur.execute('''select * from connectionreport WHERE "Threat/Content Name" = '{}' '''.format(search_item))
            rows=cur.fetchall()
            print (str(type(rows)))
            print (rows)
            return render_template('results.html', rows=rows)
        except OSError: 
            return "err " 
        else: 
            return "sql err" 
    return render_template('search.html')

@app.route('/exportcsvdst/', methods=['GET'])
def exportcsvdst():
    si = StringIO()
    cw = csv.writer(si)
    conn = psycopg2.connect(dbname='safenetworkingse', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
    cur.execute(
        'SELECT ("Destination address", "Threat/Content Name", "URL"), count(*) as count from sn1dnsthreatnameraw group by ("Destination address", "Threat/Content Name", "URL") order by count desc;')
    rows = cur.fetchall()
    cw.writerow([i[0] for i in cur.description])
    cw.writerows(rows)
    response = make_response(si.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=destiphits.csv'
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/exportcsv/', methods=['GET'])
def exportcsv():
    si = StringIO()
    cw = csv.writer(si)
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
    cur.execute(
        'select "Source address", count("Source address") from sn1dnseventsraw group by "Source address" ORDER BY 2 DESC;')
    rows = cur.fetchall()
    cw.writerow([i[0] for i in cur.description])
    cw.writerows(rows)
    response = make_response(si.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=srciphits.csv'
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/exportsrcipmalwarecat/', methods=['GET'])
def exportsrcipmalwarecat():
    si = StringIO()
    cw = csv.writer(si)
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
    cur = conn.cursor()
    cur.execute(
        'SELECT Distinct "Source address", "Destination address", "tag", "Threat/Content Name", "URL", "Time Logged" FROM connectionreport order by "Time Logged"')
    rows = cur.fetchall()
    cw.writerow([i[0] for i in cur.description])
    cw.writerows(rows)
    response = make_response(si.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=srcipwmalwarecategory.csv'
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/exportmalwarefamily/', methods=['GET'])
def exportmalwarefamily():
    si = StringIO()
    cw = csv.writer(si)
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
    cur = conn.cursor()
    cur.execute(
        'select "tags", count("tags") from afqsn where "tags" is not null group by "tags" ORDER BY 2 DESC')
    rows = cur.fetchall()
    cw.writerow([i[0] for i in cur.description])
    cw.writerows(rows)
    response = make_response(si.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=malwarefamily.csv'
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/exportcsvfiletype/', methods=['GET'])
def exportcsvfiletype():
    si = StringIO()
    cw = csv.writer(si)
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
    cur.execute('''
    SELECT filetype, COUNT(*) AS "FileType Count" 
    FROM afqsn
    GROUP BY filetype
    ''')
    rows = cur.fetchall()
    cw.writerow([i[0] for i in cur.description])
    cw.writerows(rows)
    response = make_response(si.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=malwarefiletype.csv'
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/exportdomains/', methods=['GET'])
def exportdomains():
    si = StringIO()
    cw = csv.writer(si)
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
    cur = conn.cursor()
    cur.execute(
        'SELECT distinct domain, filetype, Count(*) FROM afqsn group by domain, filetype order by count DESC')
    rows = cur.fetchall()
    cw.writerow([i[0] for i in cur.description])
    cw.writerows(rows)
    response = make_response(si.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=domainwithfile.csv'
    response.headers["Content-type"] = "text/csv"
    return response


@app.route('/TopDomains')
def TopDomains():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()

    cur.execute(
        '''select "Threat/Content Name", count("Threat/Content Name") from sn1dnseventsraw group by "Threat/Content Name" ORDER BY 2 DESC LIMIT 10''')
    bar1 = int(raw_input(" '%s' % row[1]"))
    for row in cur:
        print (row)
        line_chart = pygal.HorizontalBar()
        line_chart.title = 'Top 10 Domains (by hits)'
        line_chart.add('%s' % row[0], 8000)
        line_chart.add('%s' % row[0][0], 7000)
        line_chart.add('%s' % row[0], 6000)
        line_chart.add('%s' % row[0], [bar1])
        chart = line_chart.render(is_unicode=True)
        return render_template('TopDomains.html', chart=chart)


@app.route('/funnel/')
def Pie_route():
    
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
   
    cur.execute('''
    SELECT filetype, count(*) as count from afqsn group by filetype
    ''')
    rows = cur.fetchall()
    print(rows)
    
    chart = pygal.Pie(margin_top=10)
    pie_chart = pygal.Pie(width=700,height=500,truncate_legend=-1)
    
    pie_chart.title = 'Malware by Filetype Count'
    for row in rows:
        print (row)
        pie_chart.add('%s: %s' % (row[0], row[1]), [{'value': row[1], 'label': row[0]}])
    chart = pie_chart.render(is_unicode=True)

    return render_template('maliciousfiletypesintel.html', chart=chart)


@app.route('/domain/')
def domain_route():

    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()

    cur.execute('''
    select "Threat/Content Name", count("Threat/Content Name") from sn1dnseventsraw group by "Threat/Content Name" ORDER BY 2 DESC LIMIT 10
    ''')
    rows = cur.fetchall()
    print(rows)

    chart = pygal.Pie()
    pie_chart = pygal.Pie(width=800,height=600,truncate_legend=-1)

    pie_chart.title = 'Malware by Filetype Count'
    for row in rows:
        print (row)
        pie_chart.add('%s: %s' % (row[0], row[1]), [{'value': row[1], 'label': row[0]}])
    chart = pie_chart.render(is_unicode=True)

    return render_template('funnel.html', chart=chart)

@app.route('/domainmalicioussamples/')
def domainmalicioussamples():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')

    cur = conn.cursor()
    cur.execute('''SELECT "Threat/Content Name", "Severity", count(*) as count from sn1dnsthreatnameraw group by "Threat/Content Name", "Severity" order by count desc''')
#SELECT COALESCE ("URL", "Threat/Content Name") as domain, "Severity", count(*) as count from sn1dnsthreatnameraw group by domain, "Severity" order by count desc
#    cur.execute('''SELECT distinct domain, filetype, Count(*) FROM afqsn group by domain, filetype order by count DESC''')
    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("domainintel.html", rows=rows)


@app.route('/domainhits/')
def domainhits():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')

    cur = conn.cursor()
    cur.execute('''select "Threat/Content Name", count("Threat/Content Name") from sn1dnsthreatnameraw where "Threat/Content Name" is not null and "Threat/Content Name" != '' group by "Threat/Content Name" ORDER BY 2 DESC''')
    rows = cur.fetchall();
    print()
    conn.close()
    my_chart = BarChart("my_chart", options={'title': 'My Chart'})
    my_chart.add_column("string", "Competitor")
    my_chart.add_column("number", "Hot Dogs")
    my_chart.add_rows([["Matthew Stonie", 62],
                        ["Joey Chestnut", 60],
                        ["Eater X", 35.5],
                        ["Erik Denmark", 33],
                        ["Adrian Morgan", 31]])
    return render_template("domainhits.html", rows=rows, charts=charts)

@app.route('/edldomain/')
def edldomain():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')

    cur = conn.cursor()
    cur.execute('''select distinct "Threat/Content Name" from sn1dnsthreatnameraw where "Threat/Content Name" is not null and "Threat/Content Name" != '' group by "Threat/Content Name" ''')
    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("edldomain.html", rows=rows)

@app.route('/edlip/')
def edlip():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')

    cur = conn.cursor()
    cur.execute('''select distinct "Source address" from sn1dnsthreatnameraw''')
    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("edlip.html", rows=rows)


@app.route('/uniquethreatcountsrcdest/')
def uniquethreatcountsrcdest():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')

    cur = conn.cursor()
    cur.execute('''select distinct "Threat/Content Name", "Source address", "Destination address", Count(*) FROM sn1dnseventsraw GROUP BY "Threat/Content Name", "Source address", "Destination address" order by count DESC''')
    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("uniquethreatcountsrcdest.html", rows=rows)

@app.route('/malwarefamily/')
def malwarefamily():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()

    cur.execute('''select "tag", count("tag") from connectionreport group by "tag" ORDER BY 2 DESC''')

    rows = cur.fetchall();
    print()
    conn.close()
    return render_template("malwarefamilyintel.html", rows=rows)


@app.route('/destintel/')
def destintel():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()

    cur.execute('''
         SELECT ("Destination address", "Threat/Content Name"), count(*) as count from sn1dnsthreatnameraw group by ("Destination address", "Threat/Content Name") order by count desc
''')

    rows = cur.fetchall();
    print(rows)
    conn.close()
    return render_template("destintel.html", rows=rows)

@app.route('/searchdate/', methods=['POST','GET'])
def searchdate():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()

    cur.execute('''SELECT DISTINCT ("Destination address", "Threat/Content Name"), count(*) as count from connectionreport group by ("Destination address", "Threat/Content Name") order by count desc''')

    form = ExampleForm()
    if form.validate_on_submit():
        print(form.dt.data)
        newdata = form.dt.data
        cur.execute('''SELECT * FROM connectionreport WHERE CAST("Time Logged" AS DATE) = '{}' '''.format(newdata))   
        rows = cur.fetchall();
        print(rows)
        print(newdata)
        return render_template("autofocusintel.html.flaskdate", form=form, rows=rows)
    rows = cur.fetchall();
    print(rows)
    print(form.dt.data)
    conn.close()
    return render_template("autofocusintel.html.flaskdate", form=form, rows=rows)


@app.route('/searchdomfile', methods=['GET', 'POST'])
def searchdomfile():
    conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
    cur = conn.cursor()
#    cur.execute('''
#    SELECT filetype, count(*) as count from afqsn group by filetype
#    ''')
#
#    rows = cur.fetchall()
#    print(rows)
#
#    chart = pygal.Pie(margin_top=10)
#    pie_chart = pygal.Pie(width=700,height=300,truncate_legend=-1)

#    pie_chart.title = 'Malware by Filetype Count'
#    for row in rows:
#        print (row)
#        pie_chart.add('%s: %s' % (row[0], row[1]), [{'value': row[1], 'label': row[0]}])
#    chart = pie_chart.render(is_unicode=True)
#    return render_template('maliciousfiletypesintel.html', chart=chart)
    if request.method == "GET":
        try:
            search_item = request.args.get('search_item')
            conn = psycopg2.connect(dbname='safenetworking', user='postgres', host='127.0.0.1', password='safeNETWORKING')
            cur = conn.cursor()
            print (search_item)
            cur.execute('''SELECT filetype, count(*) filter (where "domain" = '{}') as count from afqsn group by filetype'''.format(search_item))
            rows=cur.fetchall()
            print (str(type(rows)))

            chart = pygal.Pie(margin_top=10)
            pie_chart = pygal.Pie(width=700,height=300,truncate_legend=-1)

            pie_chart.title = 'Malware by Filetype Count'
            for row in rows:
                print (row)
                pie_chart.add('%s: %s' % (row[0], row[1]), [{'value': row[1], 'label': row[0]}])
            chart = pie_chart.render(is_unicode=True)
            return render_template('maliciousfiletypesintel.html', chart=chart)
        except OSError:
            return "err "
        else:
            return render_template('maliciousfiletypesintel.html', chart=chart)
    

    

if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    context = ('39b96e5ca66dbbd0.crt', 'safenetworkingpanw.key')
    app.run(host='0.0.0.0', port=443, ssl_context=context, threaded=True, debug=True)
