import secrets
import string
import os
import io
import pandas as pd
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, func # funcをインポート
from openpyxl.styles import Border, Side # BorderとSideをインポート

# --- Flaskアプリケーションの初期設定 ---
app = Flask(__name__)
# SECRET_KEYは環境変数から取得、Renderで設定します
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_super_secret_key_for_test')
# DATABASE_URLも環境変数から取得、Renderで設定します
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///area_management.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- データベースモデルの定義 ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False) # ユーザー名はメールアドレスに固定
    name = db.Column(db.String(80), nullable=False) # 表示用の名前 (スペース除去済み)
    password_hash = db.Column(db.String(256), nullable=False) # パスワードをハッシュ化して保存 (長さを128から256に増やしました)
    affiliation = db.Column(db.String(100), nullable=True) # 所属
    is_admin = db.Column(db.Boolean, default=False) # 事務職員判定用
    is_first_login = db.Column(db.Boolean, default=True) # 初回ログインフラグ

    # パスワードハッシュ化のメソッド
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # パスワード検証のメソッド
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.email}>'

class Municipality(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    postal_code = db.Column(db.String(10), nullable=True)
    local_gov_code = db.Column(db.String(10), nullable=False, unique=True)
    prefecture = db.Column(db.String(20), nullable=False)
    city_town_village = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return '<Municipality %s %s>' % (self.prefecture, self.city_town_village)

class UserArea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    municipality_id = db.Column(db.Integer, db.ForeignKey('municipality.id'), nullable=False)
    
    user = db.relationship('User', backref=db.backref('user_areas', lazy=True))
    municipality = db.relationship('Municipality', backref=db.backref('user_areas', lazy=True))

    def __repr__(self):
        return '<UserArea User:%s Muni:%s>' % (self.user_id, self.municipality_id)

class AreaChangeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    municipality_id = db.Column(db.Integer, db.ForeignKey('municipality.id'), nullable=False)
    change_type = db.Column(db.String(20), nullable=False) # 'assigned' (対応可) or 'unassigned' (対応不可)
    change_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow) # 変更日時

    user = db.relationship('User', backref=db.backref('area_change_logs', lazy=True))
    municipality = db.relationship('Municipality', backref=db.backref('area_change_logs', lazy=True))

    def __repr__(self):
        return f'<AreaChangeLog User:{self.user_id} Muni:{self.municipality_id} Type:{self.change_type} Date:{self.change_date}>'


# --- データベースの初期化とデータ投入関数 ---
def init_db_and_data():
    with app.app_context():
        db.create_all() # 全てのテーブルを作成

        # テスト管理者ユーザーの追加 (初回実行時のみ)
        admin_email = 'admin@clp-ytmm.com' # 管理者メールアドレスもドメイン制限に合わせる
        if not User.query.filter_by(email=admin_email).first():
            admin_user = User(
                email=admin_email,
                name='管理者',
                affiliation='本社',
                is_admin=True,
                is_first_login=False # 管理者は初回ログインではないとする
            )
            admin_user.set_password('admin_password') # 管理者パスワードを設定
            db.session.add(admin_user)
            print(f"管理者ユーザー {admin_email} を追加しました。")

        # 古いテスト営業職員ユーザーが存在する場合は削除する（モデル変更のため）
        # 新しい営業職員は新規登録機能で作成される
        # 注意：これは開発環境でのマイグレーションを簡素化するためのものです。本番では適切なデータ移行戦略を検討してください。
        old_test_sales_user = User.query.filter_by(name='test_user_sales').first()
        if old_test_sales_user:
            # 関連するUserAreaとAreaChangeLogも削除
            UserArea.query.filter_by(user_id=old_test_sales_user.id).delete()
            AreaChangeLog.query.filter_by(user_id=old_test_sales_user.id).delete()
            db.session.delete(old_test_sales_user)
            print("古い 'test_user_sales' ユーザーと関連データを削除しました。")
        db.session.commit() # 変更をコミット

        # 市区町村データの読み込みと投入 (初回実行時のみ)
        # municipalities.csv ファイルからの読み込みではなく、コード内のデータを使用
        MUNICIPALITIES_CSV_DATA = """
郵便番号,地方公共団体コード,都道府県,市区町村
0600000,01101,北海道,札幌市中央区
0010000,01102,北海道,札幌市北区
0650000,01103,北海道,札幌市東区
0060800,01104,北海道,札幌市手稲区
0620000,01105,北海道,札幌市豊平区
0470000,01202,北海道,函館市
0788200,01210,北海道,旭川市
0850000,01206,北海道,釧路市
0800000,01207,北海道,帯広市
9800000,04101,宮城県,仙台市青葉区
9830000,04102,宮城県,仙台市宮城野区
9840000,04103,宮城県,仙台市若林区
9820000,04104,宮城県,仙台市太白区
9811200,04202,宮城県,名取市
9850000,04203,宮城県,塩竈市
1000000,13101,東京都,千代田区
1040000,13102,東京都,中央区
1060000,13103,東京都,港区
1600000,13104,東京都,新宿区
1120000,13105,東京都,文京区
1530000,13106,東京都,目黒区
1400000,13107,東京都,品川区
1500000,13113,東京都,渋谷区
1640000,13114,東京都,中野区
1660000,13115,東京都,杉並区
1700000,13116,東京都,豊島区
1140000,13117,東京都,北区
1160000,13118,東京都,荒川区
1740000,13119,東京都,板橋区
1200000,13120,東京都,足立区
1240000,13121,東京都,葛飾区
1300000,13122,東京都,墨田区
1350000,13123,東京都,江東区
1440000,13111,東京都,大田区
1540000,13112,東京都,世田谷区
1800000,13203,東京都,武蔵野市
1900000,13204,東京都,三鷹市
1940000,13206,東京都,町田市
2200000,14101,神奈川県,横浜市鶴見区
2300000,14102,神奈川県,横浜市神奈川区
2310000,14103,神奈川県,横浜市西区
2320000,14104,神奈川県,横浜市中区
2350000,14105,神奈川県,横浜市南区
2360000,14106,神奈川県,横浜市保土ケ谷区
2380000,14107,神奈川県,横浜市磯子区
2400000,14108,神奈川県,横浜市金沢区
2440000,14109,神奈川県,横浜市港北区
2450000,14110,神奈川県,横浜市戸塚区
2500000,14201,神奈川県,川崎市川崎区
2520000,14203,神奈川県,川崎市中原区
2540000,14204,神奈川県,川崎市高津区
2600000,14205,神奈川県,川崎市多摩区
2620000,14206,神奈川県,川崎市宮前区
4600000,23101,愛知県,名古屋市千種区
4610000,23102,愛知県,名古屋市東区
4530000,23103,愛知県,名古屋市北区
4540000,23104,愛知県,名古屋市西区
4560000,23105,愛知県,名古屋市中村区
4600000,23106,愛知県,名古屋市中区
4620000,23107,愛知県,名古屋市昭和区
4630000,23108,愛知県,名古屋市瑞穂区
4640000,23109,愛知県,名古屋市熱田区
4650000,23110,愛知県,名古屋市中川区
5300000,27101,大阪府,大阪市北区
5400000,27102,大阪府,大阪市都島区
5450000,27103,大阪府,大阪市福島区
5500000,27104,大阪府,大阪市此花区
5530000,27105,大阪府,大阪市中央区
5560000,27106,大阪府,大阪市西区
5570000,27107,大阪府,大阪市港区
5580000,27108,大阪府,大阪市大正区
5590000,27109,大阪府,大阪市天王寺区
5600000,27110,大阪府,大阪市浪速区
8100000,40101,福岡県,福岡市博多区
8120000,40130,福岡県,福岡市中央区
8140000,40131,福岡県,福岡市南区
8160000,40132,福岡県,福岡市西区
8190000,40133,福岡県,福岡市東区
8000000,40134,福岡県,福岡市城南区
8020000,40135,福岡県,福岡市早良区
"""
        
        # Municipalityテーブルが空の場合にのみ実行（本番環境では注意が必要）
        if not Municipality.query.first(): 
            print("CSVデータをコードからデータベースに投入します...")
            df = None
            try:
                # StringIOを使って文字列データをファイルのように読み込む
                # PostgreSQLではdtypeを指定しないか、カラム名を適切にマップする必要がある
                df = pd.read_csv(io.StringIO(MUNICIPALITIES_CSV_DATA), dtype={'地方公共団体コード': str, '郵便番号': str}) # 日本語列名に対応
            except Exception as e:
                print(f"データの読み込みエラーが発生しました: {e}")
                return 

            if df is not None:
                # DataFrameの列が期待通りか確認 (念のため、日本語列名でチェック)
                expected_columns = ['郵便番号', '地方公共団体コード', '都道府県', '市区町村']
                if not all(col in df.columns for col in expected_columns):
                    print(f"CSVファイルの列が期待と異なります。期待される列: {expected_columns}, 実際の列: {df.columns.tolist()}")
                    return

                for index, row in df.iterrows():
                    municipality = Municipality(
                        postal_code=row['郵便番号'],
                        local_gov_code=row['地方公共団体コード'],
                        prefecture=row['都道府県'],
                        city_town_village=row['市区町村']
                    )
                    db.session.add(municipality)
                db.session.commit()
                print("市区町村データの投入が完了しました。")
        else:
            print("市区町村データは既に投入されています。")

# --- ルート（URLと関数のマッピング）の定義 ---

# ログインページを表示
@app.route('/login', methods=['GET', 'POST'])
def login():
    # GETリクエストの場合、無条件でログイン画面を表示する
    if request.method == 'GET':
        return render_template('login.html')

    # POSTリクエスト（ログインフォーム送信）の場合の処理
    if request.method == 'POST':
        email = request.form['email'].strip() # 入力されたメールアドレス
        password = request.form['password'] # 入力されたパスワード
        user = User.query.filter_by(email=email).first() # メールアドレスでユーザーを検索

        # ユーザーが存在し、パスワードが正しい場合
        if user and user.check_password(password):
            # セッションにユーザー情報を保存
            session['user_id'] = user.id
            session['user_email'] = user.email
            session['user_name'] = user.name
            session['is_admin'] = user.is_admin
            
            # 初回ログインの場合はパスワードリセット画面へリダイレクト
            if user.is_first_login:
                flash('初回ログインです。新しいパスワードを設定してください。', 'info')
                return redirect(url_for('reset_password'))
            # 管理者の場合は管理者ダッシュボードへリダイレクト
            elif user.is_admin:
                flash('ログインしました！', 'success')
                return redirect(url_for('admin_dashboard'))
            # それ以外（営業職員）は営業職員ダッシュボードへリダイレクト
            else:
                flash('ログインしました！', 'success')
                return redirect(url_for('sales_dashboard'))
        else:
            # ログイン失敗メッセージ
            flash('メールアドレスまたはパスワードが間違っています。', 'danger')
            return render_template('login.html') # ログイン画面を再表示

# 新規登録ページを表示・処理
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip() # メールアドレス (前後の空白除去)
        affiliation = request.form['affiliation'].strip() # 所属 (前後の空白除去)
        # 名前の全角・半角スペースを除去し、前後の空白も除去
        name = request.form['name'].replace(' ', '').replace('　', '').strip() 

        # メールアドレスのドメイン検証
        if not email.endswith('@clp-ytmm.com'):
            flash('メールアドレスは "@clp-ytmm.com" ドメインである必要があります。', 'danger')
            # 入力値を保持してテンプレートを再表示
            return render_template('register.html', email=email, affiliation=affiliation, name=name)

        # メールアドレスの重複チェック
        if User.query.filter_by(email=email).first():
            flash('このメールアドレスは既に登録されています。', 'danger')
            # 入力値を保持してテンプレートを再表示
            return render_template('register.html', email=email, affiliation=affiliation, name=name)

        # 仮パスワード生成 (8桁の英数字)
        temporary_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(8))

        # 新しいユーザーオブジェクトを作成
        new_user = User(
            email=email,
            name=name,
            affiliation=affiliation,
            is_admin=False, # 新規登録されるのは営業職員とする
            is_first_login=True # 初回ログインフラグを立てる
        )
        # 仮パスワードをハッシュ化して設定
        new_user.set_password(temporary_password) 

        # データベースに追加・コミット
        db.session.add(new_user)
        db.session.commit()

        flash(f'ユーザー登録が完了しました。初回ログイン時にパスワードを変更してください。', 'success')
        # 仮パスワードを登録成功画面に表示 (実際はメールで送信するが今回は画面表示で代替)
        return render_template('registration_success.html', email=email, temporary_password=temporary_password)
    # GETリクエスト（新規登録フォーム表示）の場合の処理
    return render_template('register.html')

# 初回パスワード再設定ページを表示・処理
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    # ログインしていない場合はログイン画面へリダイレクト
    if 'user_id' not in session:
        flash('ログインしてください。', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    
    # ユーザーが見つからない場合、または初回ログインフラグが立っていない場合はログイン画面へリダイレクト
    # user が None であればユーザーが見つからない。
    # user が存在しても is_first_login が False であれば、初回ログインではない。
    if not user:
        flash('ユーザー情報が見つかりませんでした。再度ログインしてください。', 'danger')
        return redirect(url_for('login'))
    elif not user.is_first_login:
        flash('パスワードは既に設定済みです。再度パスワードをリセットするには、「パスワードを忘れた場合」をご利用ください。', 'info')
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('sales_dashboard'))


    # POSTリクエスト（パスワード再設定フォーム送信）の場合の処理
    if request.method == 'POST':
        new_password = request.form['new_password'] # 新しいパスワード
        confirm_password = request.form['confirm_password'] # 確認用パスワード

        # パスワードの一致チェック
        if new_password != confirm_password:
            flash('新しいパスワードと確認用パスワードが一致しません。', 'danger')
            return render_template('reset_password.html') # フォームを再表示

        # 新しいパスワードをハッシュ化して設定
        user.set_password(new_password)
        user.is_first_login = False # 初回ログインフラグを解除
        db.session.commit() # データベースにコミット

        flash('パスワードが正常に更新されました！', 'success') # 成功メッセージ
        # 更新後、管理者または営業職員ダッシュボードへリダイレクト
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('sales_dashboard'))

    # GETリクエスト（パスワード再設定フォーム表示）の場合の処理
    return render_template('reset_password.html')

# パスワードを忘れた場合の処理
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip()

        # メールアドレスのドメイン検証
        if not email.endswith('@clp-ytmm.com'):
            flash('メールアドレスは "@clp-ytmm.com" ドメインである必要があります。', 'danger')
            return render_template('forgot_password.html', email=email)

        user = User.query.filter_by(email=email).first()
        if user:
            # 仮パスワードを生成し、ユーザーのパスワードをリセット
            temporary_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(8))
            user.set_password(temporary_password)
            user.is_first_login = True # 初回ログイン状態に戻すことで、パスワード再設定を強制
            db.session.commit()
            
            flash('パスワードリセットリクエストを受け付けました。', 'success')
            # 実際にはここにメール送信ロジックが入る
            # 今回はデモのため、仮パスワードを画面に表示
            return render_template('forgot_password_success.html', email=email, temporary_password=temporary_password)
        else:
            flash('指定されたメールアドレスのユーザーは見つかりませんでした。', 'danger')
    return render_template('forgot_password.html')


# ログアウト機能
@app.route('/logout')
def logout():
    # セッションからユーザー情報を削除
    session.pop('user_id', None)
    session.pop('user_email', None)
    session.pop('user_name', None)
    session.pop('is_admin', None)
    flash('ログアウトしました。', 'info') # ログアウトメッセージ
    return redirect(url_for('login')) # ログイン画面へリダイレクト

# 営業職員ダッシュボード
@app.route('/sales_dashboard', methods=['GET'])
def sales_dashboard():
    # ログインしていない、または管理者権限の場合はアクセス拒否
    if 'user_id' not in session or session.get('is_admin'):
        flash('権限がありません。', 'danger')
        return redirect(url_for('login'))
    
    current_user_id = session['user_id']
    
    # 全ての市区町村データを取得 (地方公共団体コード順)
    municipalities = Municipality.query.order_by(Municipality.local_gov_code).all()
    # ユーザーが現在選択している市区町村のIDを取得
    user_areas = UserArea.query.filter_by(user_id=current_user_id).all()
    user_selected_municipality_ids = {ua.municipality_id for ua in user_areas}

    # 都道府県を地方公共団体コード順で取得
    # 各都道府県の最小の地方公共団体コードを取得し、それに基づいてソート
    prefecture_codes = db.session.query(
        Municipality.prefecture,
        func.min(Municipality.local_gov_code).label('min_local_gov_code')
    ).group_by(Municipality.prefecture).order_by('min_local_gov_code').all()
    
    prefectures = [p.prefecture for p in prefecture_codes] # prefecturesリストを更新

    return render_template(
        'sales_dashboard.html',
        municipalities=municipalities,
        user_selected_municipality_ids=user_selected_municipality_ids,
        prefectures=prefectures
    )

# 営業職員の対応エリア保存機能
@app.route('/save_sales_area', methods=['POST'])
def save_sales_area():
    # ログインしていない、または管理者権限の場合はアクセス拒否
    if 'user_id' not in session or session.get('is_admin'):
        flash('権限がありません。', 'danger')
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    selected_municipality_ids_str = request.form.getlist('selected_areas') # 選択されたエリアIDのリスト
    selected_municipality_ids = {int(mid) for mid in selected_municipality_ids_str} # セットに変換

    # 現在ユーザーが担当しているエリアを取得
    current_user_areas = UserArea.query.filter_by(user_id=current_user_id).all()
    current_user_area_ids = {ua.municipality_id for ua in current_user_areas}

    # 削除するエリアを特定し、ログに記録
    areas_to_delete = current_user_area_ids - selected_municipality_ids
    for muni_id in areas_to_delete:
        area_to_delete = UserArea.query.filter_by(user_id=current_user_id, municipality_id=muni_id).first()
        if area_to_delete:
            db.session.delete(area_to_delete)
            # 変更履歴を記録
            log_entry = AreaChangeLog(user_id=current_user_id, municipality_id=muni_id, change_type='unassigned')
            db.session.add(log_entry)

    # 追加するエリアを特定し、ログに記録
    areas_to_add = selected_municipality_ids - current_user_area_ids
    for muni_id in areas_to_add:
        new_user_area = UserArea(user_id=current_user_id, municipality_id=muni_id)
        db.session.add(new_user_area)
        # 変更履歴を記録
        log_entry = AreaChangeLog(user_id=current_user_id, municipality_id=muni_id, change_type='assigned')
        db.session.add(log_entry)

    db.session.commit() # データベースに変更をコミット
    flash('対応エリアが更新されました！', 'success') # 成功メッセージ
    return redirect(url_for('sales_dashboard')) # ダッシュボードへリダイレクト

# 営業職員の変更履歴表示
@app.route('/sales_history')
def sales_history():
    # ログインしていない、または管理者権限の場合はアクセス拒否
    if 'user_id' not in session or session.get('is_admin'):
        flash('権限がありません。', 'danger')
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    # 過去1年間の変更履歴を取得（UTCタイムゾーンで計算）
    one_year_ago = datetime.utcnow() - timedelta(days=365)

    # AreaChangeLog, Municipality, User をJOINしてデータを取得
    history_logs = db.session.query(AreaChangeLog, Municipality, User).\
        join(Municipality, AreaChangeLog.municipality_id == Municipality.id).\
        join(User, AreaChangeLog.user_id == User.id).\
        filter(AreaChangeLog.user_id == current_user_id).\
        filter(AreaChangeLog.change_date >= one_year_ago).\
        order_by(AreaChangeLog.change_date.desc()).all() # 新しい順にソート

    # 表示用に整形
    formatted_logs = []
    for log, muni, user in history_logs:
        formatted_logs.append({
            'change_date': log.change_date.strftime('%Y年%m月%d日 %H:%M'), 
            'prefecture': muni.prefecture,
            'city_town_village': muni.city_town_village,
            'change_type': '対応可' if log.change_type == 'assigned' else '対応不可'
        })

    return render_template('sales_history.html', history=formatted_logs)

# 事務職員ダッシュボード
@app.route('/admin_dashboard')
def admin_dashboard():
    # ログインしていない、または管理者権限がない場合はアクセス拒否
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))
    
    # 全ての市区町村データを取得 (地方公共団体コード順)
    all_municipalities = Municipality.query.order_by(
        Municipality.local_gov_code
    ).all()

    # 営業職員のみを取得 (名前順)
    all_users = User.query.filter_by(is_admin=False).order_by(User.name).all()

    # 各市区町村に対応するユーザーのIDをマッピングするための辞書
    municipality_user_map = {}
    for muni in all_municipalities:
        municipality_user_map[muni.id] = set() 

    # 全てのUserAreaを取得し、マッピング辞書を構築
    all_user_areas = UserArea.query.all()
    for user_area in all_user_areas:
        # 営業職員にのみ関連するエリアをマッピング
        if any(u.id == user_area.user_id for u in all_users):
            municipality_user_map[user_area.municipality_id].add(user_area.user_id)

    return render_template(
        'admin_dashboard.html',
        all_municipalities=all_municipalities,
        all_users=all_users,
        municipality_user_map=municipality_user_map
    )

# 事務職員によるユーザー管理ページ（一覧表示）
@app.route('/admin_users')
def admin_users():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))
    
    users = User.query.order_by(User.email).all() 
    return render_template('admin_users.html', users=users)

# 事務職員によるユーザー編集ページ
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id) 
    
    if user.id == session['user_id'] and user.is_admin:
        flash('ご自身の管理者権限は変更できません。', 'danger')
        return redirect(url_for('admin_users'))

    if request.method == 'POST':
        new_email = request.form['email'].strip() 
        new_name = request.form['name'].replace(' ', '').replace('　', '').strip() 
        new_affiliation = request.form['affiliation'].strip() 
        reset_password_flag = 'reset_password' in request.form 
        new_is_admin_status = 'is_admin' in request.form 

        if not new_email.endswith('@clp-ytmm.com'):
            flash('メールアドレスは "@clp-ytmm.com" ドメインである必要があります。', 'danger')
            return render_template('edit_user.html', user=user) 

        if new_email != user.email and User.query.filter_by(email=new_email).first():
            flash('このメールアドレスは既に他のユーザーに登録されています。', 'danger')
            return render_template('edit_user.html', user=user) 

        user.email = new_email
        user.name = new_name
        user.affiliation = new_affiliation
        user.is_admin = new_is_admin_status 
        
        if reset_password_flag:
            temporary_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(8))
            user.set_password(temporary_password)
            user.is_first_login = True
            flash(f'ユーザー情報を更新し、パスワードをリセットしました。新しい仮パスワード: {temporary_password} (初回ログイン時に変更が必要です)', 'success')
        else:
            flash('ユーザー情報が更新されました。', 'success')
        
        db.session.commit() 
        return redirect(url_for('admin_users')) 
    
    return render_template('edit_user.html', user=user)

# 事務職員によるユーザー削除機能
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id) 
    if user.id == session['user_id']: # ログイン中のユーザー自身は削除させない
        flash('ご自身のアカウントは削除できません。', 'danger')
        return redirect(url_for('admin_users'))
    if user.is_admin: 
        flash('管理者ユーザーは削除できません。', 'danger')
        return redirect(url_for('admin_users'))
    
    UserArea.query.filter_by(user_id=user.id).delete()
    AreaChangeLog.query.filter_by(user_id=user.id).delete()
    
    db.session.delete(user) 
    db.session.commit() 
    flash(f'ユーザー "{user.name}" と関連データが削除されました。', 'success')
    return redirect(url_for('admin_users')) 

# エリア情報をExcelでダウンロードする機能
@app.route('/download_excel', defaults={'months': 12}) # デフォルト引数を追加
@app.route('/download_excel/<int:months>') # months引数を受け取るように修正
def download_excel(months): # 関数シグネチャにmonthsを追加
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))
    
    # 選択された月数を取得 (デフォルトは12ヶ月)
    # デコレータでmonthsを受け取るようになったため、request.args.getは不要
    months_to_export = months
    # 1ヶ月から12ヶ月の範囲に制限
    if not (1 <= months_to_export <= 12):
        months_to_export = 12 

    # ダウンロードボタンを押した日が属する月を1か月目と計算
    # 現在時刻の年と月から、(months_to_export - 1)ヶ月前の月の1日を計算
    current_date = datetime.utcnow() # 現在時刻 (UTC)
    
    # 計算を開始月を見つけるための初期設定
    start_year = current_date.year
    start_month = current_date.month - (months_to_export - 1)
    
    # 月が1以下の場合は年を減らし、月を調整
    while start_month <= 0:
        start_month += 12
        start_year -= 1

    # フィルタリングの開始日 (その月の1日0時0分0秒)
    start_date_of_history = datetime(start_year, start_month, 1, 0, 0, 0, 0)


    # 全ての市区町村データを取得 (Excel出力も地方公共団体コード順に)
    all_municipalities = Municipality.query.order_by(
        Municipality.local_gov_code
    ).all()

    # 営業職員のみを取得 (名前順)
    all_users = User.query.filter_by(is_admin=False).order_by(User.name).all()

    # Excelファイルとしてメモリ上に保存するためのBytesIOオブジェクト
    output = io.BytesIO()
    # PandasのExcelWriterを使用して複数のシートを書き込む
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        # --- メインシート (対応エリア一覧) ---
        header_main = ['郵便番号', '地方公共団体コード', '住所①', '住所②']
        user_names_main = [user.name for user in all_users] # Excelヘッダーにユーザー名を使用
        header_main.extend(user_names_main)

        data_rows_main = []
        for municipality in all_municipalities:
            row_main = [
                municipality.postal_code if municipality.postal_code else '', # 郵便番号（ない場合は空文字列）
                municipality.local_gov_code,
                municipality.prefecture,
                municipality.city_town_village
            ]
            for user in all_users:
                # ユーザーがその市区町村を担当しているかチェック
                is_assigned = db.session.query(UserArea).filter_by(
                    user_id=user.id, municipality_id=municipality.id
                ).first() is not None
                row_main.append('〇' if is_assigned else '') # 担当していれば「〇」、そうでなければ空文字列
            data_rows_main.append(row_main)
        
        # DataFrameを作成し、Excelシートに書き込み
        df_main = pd.DataFrame(data_rows_main, columns=header_main)
        df_main.to_excel(writer, index=False, sheet_name='対応エリア一覧')

        # ExcelWriterのwriterオブジェクトからWorkbookを取得
        workbook = writer.book
        
        # --- 「対応エリア一覧」シートの書式設定 ---
        if '対応エリア一覧' in workbook.sheetnames:
            sheet_main = workbook['対応エリア一覧']
            
            # 「住所②」列の幅を設定 (D列)
            sheet_main.column_dimensions['D'].width = 20.75

            # すべてのセルから罫線を削除
            no_border = Border(left=Side(style=None), 
                               right=Side(style=None), 
                               top=Side(style=None), 
                               bottom=Side(style=None))
            for row in sheet_main.iter_rows():
                for cell in row:
                    cell.border = no_border

        # --- 変更履歴シート (フィルタリング適用) ---
        history_logs = db.session.query(AreaChangeLog, Municipality, User).\
            join(Municipality, AreaChangeLog.municipality_id == Municipality.id).\
            join(User, AreaChangeLog.user_id == User.id).\
            filter(AreaChangeLog.change_date >= start_date_of_history).\
            order_by(AreaChangeLog.change_date.asc()).all() 

        # 月ごとの変更を辞書に集計
        # 例: {'YYYY年MM月': {'ユーザー名': {'assigned': [エリア名1, ...], 'unassigned': [エリア名2, ...]}, ...}}
        monthly_changes = {} 
        for log, muni, user in history_logs:
            change_month = log.change_date.strftime('%Y年%m月') # 変更があった年月
            user_name = user.name # 変更を行ったユーザーの名前
            area_name = f"{muni.prefecture}{muni.city_town_village}" # エリア名
            change_type = log.change_type # 'assigned' or 'unassigned'

            # 辞書構造を初期化
            if change_month not in monthly_changes:
                monthly_changes[change_month] = {}
            if user_name not in monthly_changes[change_month]:
                monthly_changes[change_month][user_name] = {'assigned': [], 'unassigned': []}
            
            # 変更内容をリストに追加
            monthly_changes[change_month][user_name][change_type].append(area_name)
        
        # 集計データをDataFrameに変換するためのリスト
        history_data_summary = []
        # 月、ユーザー名の順でソートしてデータを整形
        for month in sorted(monthly_changes.keys()):
            for user_name in sorted(monthly_changes[month].keys()):
                assigned_areas = "、".join(monthly_changes[month][user_name]['assigned']) # 追加されたエリアをカンマ区切りで結合
                unassigned_areas = "、".join(monthly_changes[month][user_name]['unassigned']) # 削除されたエリアをカンマ区切りで結合
                
                history_data_summary.append({
                    '対象月': month,
                    '営業職員名': user_name,
                    '対応可能エリア追加': assigned_areas,
                    '対応可能エリア削除': unassigned_areas
                })
        
        # 履歴のDataFrameを作成
        df_history = pd.DataFrame(history_data_summary)
        
        # データがある場合のみシートを追加。ない場合はメッセージを記載したシートを作成
        if not df_history.empty:
            df_history.to_excel(writer, index=False, sheet_name='エリア変更履歴_月次')
            # --- 「エリア変更履歴_月次」シートの書式設定 ---
            sheet_history = workbook['エリア変更履歴_月次']
            # すべてのセルから罫線を削除
            for row in sheet_history.iter_rows():
                for cell in row:
                    cell.border = no_border # 上で定義したno_borderを使用
        else:
            empty_df = pd.DataFrame({'メッセージ': ['選択された期間のエリア変更履歴はありません。']})
            empty_df.to_excel(writer, index=False, sheet_name='エリア変更履歴_月次')
            sheet_history = workbook['エリア変更履歴_月次'] # empty_dfでもシートは作成されるので取得
            for row in sheet_history.iter_rows():
                for cell in row:
                    cell.border = no_border


    # BytesIOオブジェクトの先頭にシーク
    output.seek(0) 

    # ファイル名に現在の日時（年、月、日、時、分、秒）を含める
    filename = f"area_list_{datetime.now().strftime('%Y%m%d%H%M%S')}.xlsx"

    # 生成したExcelファイルをHTTPレスポンスとして返す
    return Response(
        output.getvalue(),
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

# --- 新しい市区町村データ一括更新機能 ---
@app.route('/admin_upload_municipalities', methods=['GET', 'POST'])
def admin_upload_municipalities():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))

    additions = []
    updates = []
    deletions = []
    processing_error = None

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('ファイルが選択されていません。', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('ファイルが選択されていません。', 'danger')
            return redirect(request.url)
        
        if file and file.filename.endswith('.csv'):
            try:
                # ファイルをメモリに読み込み、Pandasで処理
                file_content = io.BytesIO(file.read())
                df = None
                # ★日本語列名を指定して読み込む★
                read_csv_params = {'dtype': {'地方公共団体コード': str, '郵便番号': str}} 
                
                try:
                    df = pd.read_csv(file_content, encoding='utf-8', **read_csv_params)
                except UnicodeDecodeError:
                    file_content.seek(0) # ストリームを先頭に戻す
                    df = pd.read_csv(file_content, encoding='cp932', **read_csv_params)

                # ★期待される列名も日本語に★
                expected_columns = ['郵便番号', '地方公共団体コード', '都道府県', '市区町村'] 
                if not all(col in df.columns for col in expected_columns):
                    processing_error = f"CSVファイルの列が期待と異なります。期待される列: {expected_columns}, 実際の列: {df.columns.tolist()}"
                
                # local_gov_code の重複チェック (日本語列名でアクセス)
                if df['地方公共団体コード'].duplicated().any(): # ★日本語列名に変更★
                    duplicate_codes = df[df['地方公共団体コード'].duplicated()]['地方公共団体コード'].tolist() # ★日本語列名に変更★
                    processing_error = f"CSVファイル内に重複する地方公共団体コードがあります: {', '.join(duplicate_codes)}"

                if not processing_error:
                    # 既存の市区町村データを取得し、地方公共団体コードをキーとする辞書を作成
                    existing_municipalities = {
                        m.local_gov_code: m for m in Municipality.query.all()
                    }
                    existing_codes = set(existing_municipalities.keys())
                    new_codes = set()

                    for index, row in df.iterrows():
                        local_gov_code = str(row['地方公共団体コード']).strip() # ★日本語列名から取得★
                        new_codes.add(local_gov_code)

                        # CSVデータの整形（NoneやNaNを空文字列に変換） - ★日本語列名から取得★
                        postal_code = str(row['郵便番号']).strip() if pd.notna(row['郵便番号']) else ''
                        prefecture = str(row['都道府県']).strip() if pd.notna(row['都道府県']) else ''
                        city_town_village = str(row['市区町村']).strip() if pd.notna(row['市区町村']) else ''

                        if local_gov_code in existing_codes:
                            # 既存の市区町村を更新
                            existing_muni = existing_municipalities[local_gov_code]
                            # 変更があったかチェック
                            if (existing_muni.postal_code != postal_code or
                                existing_muni.prefecture != prefecture or
                                existing_muni.city_town_village != city_town_village):
                                updates.append({
                                    'local_gov_code': local_gov_code,
                                    'old_postal_code': existing_muni.postal_code,
                                    'new_postal_code': postal_code,
                                    'old_prefecture': existing_muni.prefecture,
                                    'new_prefecture': prefecture,
                                    'old_city_town_village': existing_muni.city_town_village,
                                    'new_city_town_village': city_town_village
                                })
                        else:
                            # 新規追加
                            additions.append({
                                'postal_code': postal_code,
                                'local_gov_code': local_gov_code,
                                'prefecture': prefecture,
                                'city_town_village': city_town_village
                            })
                    
                    # 削除される市区町村を特定
                    deletions_codes = existing_codes - new_codes
                    for code in deletions_codes:
                        muni = existing_municipalities[code]
                        deletions.append({
                            'postal_code': muni.postal_code,
                            'local_gov_code': muni.local_gov_code,
                            'prefecture': muni.prefecture,
                            'city_town_village': muni.city_town_village
                        })
                    
                    # プレビューデータをセッションに保存
                    session['pending_additions'] = additions
                    session['pending_updates'] = updates
                    session['pending_deletions'] = deletions

                    if not additions and not updates and not deletions:
                        flash('CSVファイルと既存のデータに差異はありませんでした。', 'info')
                        return redirect(url_for('admin_dashboard')) # 変更がない場合はダッシュボードへ戻る
                    else:
                        flash('CSVデータを読み込みました。以下の変更が適用されます。内容を確認し「確定して実行」してください。', 'info')

            except pd.errors.EmptyDataError:
                processing_error = 'CSVファイルが空です。'
            except pd.errors.ParserError:
                processing_error = 'CSVファイルの解析に失敗しました。形式を確認してください。'
            except UnicodeDecodeError:
                processing_error = 'CSVファイルのエンコーディングがUTF-8またはShift-JISではありません。'
            except Exception as e:
                processing_error = f'CSV処理中にエラーが発生しました: {e}'
            
            if processing_error:
                flash(f'CSV処理エラー: {processing_error}', 'danger')
                # エラーの場合はプレビューデータをクリア
                session.pop('pending_additions', None)
                session.pop('pending_updates', None)
                session.pop('pending_deletions', None)

        else:
            flash('CSVファイルを選択してください。', 'danger')

    return render_template(
        'admin_upload_municipalities.html',
        additions=session.get('pending_additions', []),
        updates=session.get('pending_updates', []),
        deletions=session.get('pending_deletions', [])
    )

@app.route('/admin_execute_municipality_update', methods=['POST'])
def admin_execute_municipality_update():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))

    # セッションからプレビューデータを取得
    additions = session.pop('pending_additions', [])
    updates = session.pop('pending_updates', [])
    deletions = session.pop('pending_deletions', [])

    if not additions and not updates and not deletions:
        flash('適用する変更がありません。', 'warning')
        return redirect(url_for('admin_dashboard'))

    try:
        # 削除の実行 (関連データも削除)
        for muni_data in deletions:
            muni_to_delete = Municipality.query.filter_by(local_gov_code=muni_data['local_gov_code']).first()
            if muni_to_delete:
                # 関連するUserAreaとAreaChangeLogをまず削除
                UserArea.query.filter_by(municipality_id=muni_to_delete.id).delete()
                AreaChangeLog.query.filter_by(municipality_id=muni_to_delete.id).delete()
                db.session.delete(muni_to_delete)
        
        # 追加の実行
        for item_data in additions:
            new_municipality = Municipality(
                postal_code=item_data['postal_code'],
                local_gov_code=item_data['local_gov_code'],
                prefecture=item_data['prefecture'],
                city_town_village=item_data['city_town_village']
            )
            db.session.add(new_municipality)
        
        # 更新の実行
        for muni_data in updates:
            muni_to_update = Municipality.query.filter_by(local_gov_code=muni_data['local_gov_code']).first()
            if muni_to_update:
                muni_to_update.postal_code = muni_data['new_postal_code']
                muni_to_update.prefecture = muni_data['new_prefecture']
                muni_to_update.city_town_village = muni_data['new_city_town_village']
        
        db.session.commit()
        flash(f'市区町村データが正常に更新されました！ (追加: {len(additions)}件, 更新: {len(updates)}件, 削除: {len(deletions)}件)', 'success')

    except Exception as e:
        db.session.rollback() # エラー時はロールバック
        flash(f'市区町村データの更新中にエラーが発生しました: {e}', 'danger')
        # エラー発生時は、再度プレビューデータがセッションに残るようにする
        session['pending_additions'] = additions
        session['pending_updates'] = updates
        session['pending_deletions'] = deletions
    
    return redirect(url_for('admin_dashboard'))

# トップページにアクセスした際にログインページへリダイレクト
@app.route('/')
def index():
    return redirect(url_for('login'))

# --- アプリケーションの実行 ---
if __name__ == '__main__':
    # データベースの初期化とデータ投入
    init_db_and_data()
    
    # Flaskアプリケーションを起動
    # debug=True にすると、コード変更時に自動で再起動し、デバッグ情報が表示されます。
    app.run(debug=True)
