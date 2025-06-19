import secrets
import string
import os
import io
import pandas as pd
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_ # or_ をインポート

# --- Flaskアプリケーションの初期設定 ---
app = Flask(__name__)
# 環境変数からSECRET_KEYを読み込む。なければデフォルト値（開発用）
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_super_secret_key_for_local_dev') 

# データベースURIを環境変数から読み込む
# RenderではDATABASE_URLという環境変数にPostgreSQLの接続情報が設定されます
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///area_management.db')

# PostgreSQLのURLの場合、psycopg2ドライバを指定するために'postgresql'を'postgresql+psycopg2'に置換
# アプリケーション初期化の早い段階でURIを修正
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgresql://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgresql://", "postgresql+psycopg2://")
    print(f"データベースURIをPostgreSQL用に設定しました: {app.config['SQLALCHEMY_DATABASE_URI']}")
else:
    print("DATABASE_URL環境変数が設定されていないため、SQLiteを使用します。")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- データベースモデルの定義 (変更なし) ---
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
        # db.create_all() は、テーブルが存在しない場合にのみ作成します
        # 既に存在するテーブルは再作成しません。
        db.create_all() 

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
        old_test_sales_user = User.query.filter_by(name='test_user_sales').first() # 古いnameカラムで検索
        if old_test_sales_user:
            # 関連するUserAreaとAreaChangeLogも削除
            UserArea.query.filter_by(user_id=old_test_sales_user.id).delete()
            AreaChangeLog.query.filter_by(user_id=old_test_sales_user.id).delete()
            db.session.delete(old_test_sales_user)
            print("古い 'test_user_sales' ユーザーと関連データを削除しました。")
        db.session.commit() # 変更をコミット

        # 市区町村データの読み込みと投入 (初回実行時のみ)
        csv_file_path = 'municipalities.csv'
        
        # Municipalityテーブルが空の場合、かつcsvファイルが存在する場合のみデータ投入
        if not Municipality.query.first() and os.path.exists(csv_file_path):
            print(f"{csv_file_path}から市区町村データを投入します...")
            df = None
            # local_gov_codeとpostal_codeを明示的に文字列として読み込む
            read_csv_params = {'dtype': {'地方公共団体コード': str, '郵便番号': str}} 
            try:
                # まずはutf-8で試行
                df = pd.read_csv(csv_file_path, encoding='utf-8', **read_csv_params)
            except UnicodeDecodeError:
                print("utf-8での読み込みに失敗しました。cp932 (Shift-JIS) で再試行します。")
                try:
                    # utf-8で失敗した場合、cp932で試行
                    df = pd.read_csv(csv_file_path, encoding='cp932', **read_csv_params)
                except Exception as e: 
                    print(f"CSVファイルの読み込みエラー: cp932 (Shift-JIS) でも読み込みに失敗しました。")
                    print(f"ファイルが壊れているか、別のエンコーディングの可能性があります。エラー: {e}")
                    return 
            except Exception as e: 
                print(f"CSVファイルの読み込み中に予期せぬエラーが発生しました: {e}")
                return

            if df is not None: 
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
                print("市区町村データの読み込みに失敗したため、データベースへの投入をスキップします。")
        elif not os.path.exists(csv_file_path):
            print(f"WARNING: {csv_file_path}が見つかりません。市区町村データが投入されません。")
        else:
            print("市区町村データは既に投入されています。")

# --- Flaskアプリケーションのコンテキストが準備できた後にデータベースを初期化 ---
# これにより、Gunicornによって起動された場合でもdb.create_all()が確実に実行されます。
with app.app_context():
    init_db_and_data()

# --- ルート（URLと関数のマッピング）の定義 (変更なし) ---

# ログインページを表示
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            if user.is_first_login: 
                return redirect(url_for('reset_password'))
            elif user.is_admin: 
                return redirect(url_for('admin_dashboard'))
            else: 
                return redirect(url_for('sales_dashboard'))

    if request.method == 'POST':
        email = request.form['email'].strip() 
        password = request.form['password'] 
        user = User.query.filter_by(email=email).first() 

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['user_email'] = user.email
            session['user_name'] = user.name
            session['is_admin'] = user.is_admin
            flash('ログインしました！', 'success') 
            
            if user.is_first_login:
                return redirect(url_for('reset_password'))
            elif user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('sales_dashboard'))
        else:
            flash('メールアドレスまたはパスワードが間違っています。', 'danger')
    return render_template('login.html')

# 新規登録ページを表示・処理
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip() 
        affiliation = request.form['affiliation'].strip() 
        name = request.form['name'].replace(' ', '').replace('　', '').strip() 

        if not email.endswith('@clp-ytmm.com'):
            flash('メールアドレスは "@clp-ytmm.com" ドメインである必要があります。', 'danger')
            return render_template('register.html', email=email, affiliation=affiliation, name=name)

        if User.query.filter_by(email=email).first():
            flash('このメールアドレスは既に登録されています。', 'danger')
            return render_template('register.html', email=email, affiliation=affiliation, name=name)

        temporary_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(8))

        new_user = User(
            email=email,
            name=name,
            affiliation=affiliation,
            is_admin=False, 
            is_first_login=True 
        )
        new_user.set_password(temporary_password) 

        try:
            db.session.add(new_user)
            db.session.commit()

            # 成功したら、registration_success.html にリダイレクトし、仮パスワードを渡す
            flash(f'ユーザー登録が完了しました。初回ログイン時にパスワードを変更してください。', 'success')
            return render_template('registration_success.html', email=email, temporary_password=temporary_password)
        except Exception as e:
            db.session.rollback() 
            flash(f'ユーザー登録中にエラーが発生しました。もう一度お試しください。 ({e})', 'danger')
            # エラー時も入力値を保持してテンプレートを再表示
            return render_template('register.html', email=email, affiliation=affiliation, name=name)

    return render_template('register.html')

# 初回パスワード再設定ページを表示・処理
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'user_id' not in session:
        flash('ログインしてください。', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        flash('ユーザーが見つかりません。', 'danger')
        return redirect(url_for('login'))

    if not user.is_first_login:
        flash('パスワードは既に設定済みです。', 'info')
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('sales_dashboard'))

    if request.method == 'POST':
        new_password = request.form['new_password'] 
        confirm_password = request.form['confirm_password'] 

        if new_password != confirm_password:
            flash('新しいパスワードと確認用パスワードが一致しません。', 'danger')
            return render_template('reset_password.html') 

        user.set_password(new_password)
        user.is_first_login = False 
        db.session.commit() 

        flash('パスワードが正常に更新されました！', 'success') 
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('sales_dashboard'))

    return render_template('reset_password.html')

# パスワードを忘れた場合の処理
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip()

        if not email.endswith('@clp-ytmm.com'):
            flash('メールアドレスは "@clp-ytmm.com" ドメインである必要があります。', 'danger')
            return render_template('forgot_password.html', email=email)

        user = User.query.filter_by(email=email).first()
        if user:
            temporary_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(8))
            user.set_password(temporary_password)
            user.is_first_login = True 
            db.session.commit()
            
            flash('パスワードリセットリクエストを受け付けました。', 'success')
            return render_template('forgot_password_success.html', email=email, temporary_password=temporary_password)
        else:
            flash('指定されたメールアドレスのユーザーは見つかりませんでした。', 'danger')
    return render_template('forgot_password.html')


# ログアウト機能
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_email', None)
    session.pop('user_name', None)
    session.pop('is_admin', None)
    flash('ログアウトしました。', 'info') 
    return redirect(url_for('login')) 

# 営業職員ダッシュボード
@app.route('/sales_dashboard', methods=['GET'])
def sales_dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        flash('権限がありません。', 'danger')
        return redirect(url_for('login'))
    
    current_user_id = session['user_id']
    
    municipalities = Municipality.query.order_by(Municipality.local_gov_code).all()
    user_areas = UserArea.query.filter_by(user_id=current_user_id).all()
    user_selected_municipality_ids = {ua.municipality_id for ua in user_areas}

    prefectures = sorted(list(set(m.prefecture for m in municipalities)))

    return render_template(
        'sales_dashboard.html',
        municipalities=municipalities,
        user_selected_municipality_ids=user_selected_municipality_ids,
        prefectures=prefectures
    )

# 営業職員の対応エリア保存機能
@app.route('/save_sales_area', methods=['POST'])
def save_sales_area():
    if 'user_id' not in session or session.get('is_admin'):
        flash('権限がありません。', 'danger')
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    selected_municipality_ids_str = request.form.getlist('selected_areas') 
    selected_municipality_ids = {int(mid) for mid in selected_municipality_ids_str} 

    current_user_areas = UserArea.query.filter_by(user_id=current_user_id).all()
    current_user_area_ids = {ua.municipality_id for ua in current_user_areas}

    areas_to_delete = current_user_area_ids - selected_municipality_ids
    for muni_id in areas_to_delete:
        area_to_delete = UserArea.query.filter_by(user_id=current_user_id, municipality_id=muni_id).first()
        if area_to_delete:
            db.session.delete(area_to_delete)
            log_entry = AreaChangeLog(user_id=current_user_id, municipality_id=muni_id, change_type='unassigned')
            db.session.add(log_entry)

    areas_to_add = selected_municipality_ids - current_user_area_ids
    for muni_id in areas_to_add:
        new_user_area = UserArea(user_id=current_user_id, municipality_id=muni_id)
        db.session.add(new_user_area)
        log_entry = AreaChangeLog(user_id=current_user_id, municipality_id=muni_id, change_type='assigned')
        db.session.add(log_entry)

    db.session.commit() 
    flash('対応エリアが更新されました！', 'success') 
    return redirect(url_for('sales_dashboard')) 

# 営業職員の変更履歴表示
@app.route('/sales_history')
def sales_history():
    if 'user_id' not in session or session.get('is_admin'):
        flash('権限がありません。', 'danger')
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    one_year_ago = datetime.utcnow() - timedelta(days=365)

    history_logs = db.session.query(AreaChangeLog, Municipality, User).\
        join(Municipality, AreaChangeLog.municipality_id == Municipality.id).\
        join(User, AreaChangeLog.user_id == User.id).\
        filter(AreaChangeLog.user_id == current_user_id).\
        filter(AreaChangeLog.change_date >= one_year_ago).\
        order_by(AreaChangeLog.change_date.desc()).all() 

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
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))
    
    all_municipalities = Municipality.query.order_by(
        Municipality.local_gov_code
    ).all()

    all_users = User.query.filter_by(is_admin=False).order_by(User.name).all()

    municipality_user_map = {}
    for muni in all_municipalities:
        municipality_user_map[muni.id] = set() 

    all_user_areas = UserArea.query.all()
    for user_area in all_user_areas:
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
    if user.is_admin: 
        flash('管理者ユーザーは削除できません。', 'danger')
        return redirect(url_for('admin_users'))
    
    UserArea.query.filter_by(user_id=user.id).delete()
    AreaChangeLog.query.filter_by(user_id=user.id).delete()
    
    db.session.delete(user) 
    db.session.commit() 
    flash('ユーザーが正常に削除されました。', 'success')
    return redirect(url_for('admin_users')) 


# 事務職員による市区町村データアップロードページを表示・処理
@app.route('/admin_upload_municipalities', methods=['GET', 'POST'])
def admin_upload_municipalities():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))

    additions = []
    updates = []
    deletions = []

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('ファイルがアップロードされていません。', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('ファイルが選択されていません。', 'danger')
            return redirect(request.url)

        if file:
            try:
                df = None
                read_csv_params = {'dtype': {'地方公共団体コード': str, '郵便番号': str}} 
                
                try:
                    file_content = file.stream.read().decode('utf-8')
                    df = pd.read_csv(io.StringIO(file_content), **read_csv_params)
                except UnicodeDecodeError:
                    file.stream.seek(0) 
                    file_content = file.stream.read().decode('cp932')
                    df = pd.read_csv(io.StringIO(file_content), **read_csv_params)

                expected_columns = ['郵便番号', '地方公共団体コード', '都道府県', '市区町村']
                if not all(col in df.columns for col in expected_columns):
                    flash(f'CSVファイルの列名が正しくありません。以下の列が必要です: {", ".join(expected_columns)}', 'danger')
                    return render_template('admin_upload_municipalities.html')

                existing_municipalities = {m.local_gov_code: m for m in Municipality.query.all()}
                
                uploaded_local_gov_codes = set(df['地方公共団体コード'].tolist())

                for index, row in df.iterrows():
                    local_gov_code = row['地方公共団体コード']
                    if local_gov_code not in existing_municipalities:
                        additions.append(Municipality(
                            postal_code=row['郵便番号'],
                            local_gov_code=local_gov_code,
                            prefecture=row['都道府県'],
                            city_town_village=row['市区町村']
                        ))
                
                for local_gov_code, existing_muni in existing_municipalities.items():
                    if local_gov_code in uploaded_local_gov_codes:
                        new_data = df[df['地方公共団体コード'] == local_gov_code].iloc[0]
                        
                        is_updated = False
                        update_info = {
                            'local_gov_code': local_gov_code,
                            'old_postal_code': existing_muni.postal_code,
                            'new_postal_code': new_data['郵便番号'],
                            'old_prefecture': existing_muni.prefecture,
                            'new_prefecture': new_data['都道府県'],
                            'old_city_town_village': existing_muni.city_town_village,
                            'new_city_town_village': new_data['市区町村']
                        }
                        
                        if str(existing_muni.postal_code) != str(new_data['郵便番号']) or \
                           existing_muni.prefecture != new_data['都道府県'] or \
                           existing_muni.city_town_village != new_data['市区町村']:
                            is_updated = True
                            
                        if is_updated:
                            updates.append(update_info)

                for local_gov_code, existing_muni in existing_municipalities.items():
                    if local_gov_code not in uploaded_local_gov_codes:
                        deletions.append(existing_muni)
                
                if not additions and not updates and not deletions:
                    flash('CSVファイルの内容は現在のデータと一致しています。変更はありませんでした。', 'info')

                # ここで Municipalityオブジェクトを直接セッションに保存せず、辞書形式に変換して保存
                # render_templateに渡す際は、辞書からMunicipalityオブジェクトに再構築
                session['municipality_additions'] = [municipality_to_dict(m) for m in additions] 
                session['municipality_updates'] = updates
                session['municipality_deletions'] = [municipality_to_dict(m) for m in deletions] 

            except Exception as e:
                flash(f'CSVファイルの読み込みまたは解析中にエラーが発生しました: {e}', 'danger')
                return render_template('admin_upload_municipalities.html')

    # Municipalityオブジェクトを辞書に変換するヘルパー関数
    def municipality_to_dict(muni):
        return {
            'id': muni.id if hasattr(muni, 'id') else None,
            'postal_code': muni.postal_code,
            'local_gov_code': muni.local_gov_code,
            'prefecture': muni.prefecture,
            'city_town_village': muni.city_town_village
        }
    
    # セッションからデータを取得し、Municipalityオブジェクトに再構築してテンプレートに渡す
    # セッションにデータがない場合は空のリスト
    additions = [Municipality(**d) for d in session.get('municipality_additions', [])]
    updates = session.get('municipality_updates', [])
    deletions = [Municipality(**d) for d in session.get('municipality_deletions', [])]


    return render_template(
        'admin_upload_municipalities.html',
        additions=additions,
        updates=updates,
        deletions=deletions
    )

# 市区町村データの更新を実行するルート
@app.route('/admin_execute_municipality_update', methods=['POST'])
def admin_execute_municipality_update():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))
    
    try:
        additions_data = session.pop('municipality_additions', [])
        updates_data = session.pop('municipality_updates', [])
        deletions_data = session.pop('municipality_deletions', [])

        deletion_local_gov_codes = {d['local_gov_code'] for d in deletions_data}
        
        if deletion_local_gov_codes:
            municipalities_to_delete_ids = db.session.query(Municipality.id).filter(
                Municipality.local_gov_code.in_(deletion_local_gov_codes)
            ).subquery()

            AreaChangeLog.query.filter(
                AreaChangeLog.municipality_id.in_(municipalities_to_delete_ids)
            ).delete(synchronize_session=False)

            UserArea.query.filter(
                UserArea.municipality_id.in_(municipalities_to_delete_ids)
            ).delete(synchronize_session=False)

            Municipality.query.filter(
                Municipality.local_gov_code.in_(deletion_local_gov_codes)
            ).delete(synchronize_session=False)
            print(f"市区町村データ {deletion_local_gov_codes} を削除しました。関連するUserAreaとAreaChangeLogも削除されました。")

        for item_data in additions_data:
            new_muni = Municipality(
                postal_code=item_data['postal_code'],
                local_gov_code=item_data['local_gov_code'],
                prefecture=item_data['prefecture'],
                city_town_village=item_data['city_town_village']
            )
            db.session.add(new_muni)
            print(f"新規市区町村 {new_muni.city_town_village} を追加しました。")

        for item_data in updates_data:
            existing_muni = Municipality.query.filter_by(local_gov_code=item_data['local_gov_code']).first()
            if existing_muni:
                existing_muni.postal_code = item_data['new_postal_code']
                existing_muni.prefecture = item_data['new_prefecture']
                existing_muni.city_town_village = item_data['new_city_town_village']
                print(f"市区町村 {existing_muni.city_town_village} を更新しました。")
        
        db.session.commit() 
        flash('市区町村データが正常に更新されました！', 'success')

    except Exception as e:
        db.session.rollback() 
        flash(f'市区町村データの更新中にエラーが発生しました: {e}', 'danger')
        print(f"市区町村データの更新エラー: {e}")

    return redirect(url_for('admin_dashboard'))


# トップページをログインページにリダイレクト
@app.route('/')
def index():
    return redirect(url_for('login'))


# --- アプリケーションの実行 (開発環境用) ---
if __name__ == '__main__':
    # Flask開発サーバーはGunicornとは異なり、自動でinit_db_and_data()を呼び出す
    # ここはRenderデプロイ時には実行されないため、影響はありません
    app.run(debug=True)

