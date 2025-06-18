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

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- データベースモデルの定義 ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False) # ユーザー名はメールアドレスに固定
    name = db.Column(db.String(80), nullable=False) # 表示用の名前 (スペース除去済み)
    password_hash = db.Column(db.String(128), nullable=False) # パスワードをハッシュ化して保存
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
        # PostgreSQLの場合のURLを修正して、psycopg2-binaryが認識できるようにする
        # 環境変数DATABASE_URLが設定されているか確認
        if 'DATABASE_URL' in os.environ:
            # PostgreSQLのURLの場合、psycopg2ドライバを指定するために'postgresql'を'postgresql+psycopg2'に置換
            # RenderのDATABASE_URLは 'postgresql://' で始まるため、これを利用します
            current_db_uri = app.config['SQLALCHEMY_DATABASE_URI']
            if current_db_uri.startswith("postgresql://"):
                app.config['SQLALCHEMY_DATABASE_URI'] = current_db_uri.replace("postgresql://", "postgresql+psycopg2://")
                print(f"データベースURIをPostgreSQL用に設定しました: {app.config['SQLALCHEMY_DATABASE_URI']}")
        else:
            print("DATABASE_URL環境変数が設定されていないため、SQLiteを使用します。")

        # データベースの再初期化（テーブルが存在する場合は削除して再作成）
        # Renderでは永続化されないため、毎回テーブルを再作成するロジックは必要ないことが多いですが、
        # 初期データの投入を確実にするため、もしテーブルが存在しなければ作成します。
        # 本番環境では db.create_all() は初回のみ実行し、以降はマイグレーションツール(Alembicなど)を使用することを推奨
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
        
        if not Municipality.query.first() and os.path.exists(csv_file_path):
            print(f"{csv_file_path}から市区町村データを投入します...")
            df = None
            # local_gov_codeとpostal_codeを明示的に文字列として読み込む
            read_csv_params = {'dtype': {'地方公共団体コード': str, '郵便番号': str}} # ★日本語列名に変更★
            try:
                # まずはutf-8で試行
                df = pd.read_csv(csv_file_path, encoding='utf-8', **read_csv_params)
            except UnicodeDecodeError:
                print("utf-8での読み込みに失敗しました。cp932 (Shift-JIS) で再試行します。")
                try:
                    # utf-8で失敗した場合、cp932で試行
                    df = pd.read_csv(csv_file_path, encoding='cp932', **read_csv_params)
                except Exception as e: # より広範なエラーをキャッチ
                    print(f"CSVファイルの読み込みエラー: cp932 (Shift-JIS) でも読み込みに失敗しました。")
                    print(f"ファイルが壊れているか、別のエンコーディングの可能性があります。エラー: {e}")
                    return # 処理を中断
            except Exception as e: # その他のファイル読み込みエラー
                print(f"CSVファイルの読み込み中に予期せぬエラーが発生しました: {e}")
                return

            if df is not None: # dfが正常に読み込まれた場合のみ処理を続行
                # DataFrameの列が期待通りか確認 (念のため)
                expected_columns = ['郵便番号', '地方公共団体コード', '都道府県', '市区町村'] # ★日本語列名に変更★
                if not all(col in df.columns for col in expected_columns):
                    print(f"CSVファイルの列が期待と異なります。期待される列: {expected_columns}, 実際の列: {df.columns.tolist()}")
                    return # 処理を中断

                for index, row in df.iterrows():
                    municipality = Municipality(
                        postal_code=row['郵便番号'], # ★日本語列名から取得★
                        local_gov_code=row['地方公共団体コード'], # ★日本語列名から取得★
                        prefecture=row['都道府県'], # ★日本語列名から取得★
                        city_town_village=row['市区町村'] # ★日本語列名から取得★
                    )
                    db.session.add(municipality)
                db.session.commit()
                print("市区町村データの投入が完了しました。")
            else: # dfがNoneの場合 (読み込みエラーでreturnしなかったがdfがNoneの場合)
                print("市区町村データの読み込みに失敗したため、データベースへの投入をスキップします。")
        elif not os.path.exists(csv_file_path):
            print(f"WARNING: {csv_file_path}が見つかりません。市区町村データが投入されません。")
        else:
            print("市区町村データは既に投入されています。")

# --- ルート（URLと関数のマッピング）の定義 ---

# ログインページを表示
@app.route('/login', methods=['GET', 'POST'])
def login():
    # 既にログイン済みの場合は、初回ログイン状態や管理者権限に応じて適切なダッシュボードへリダイレクト
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            if user.is_first_login: # 初回ログインの場合はパスワードリセット画面へ
                return redirect(url_for('reset_password'))
            elif user.is_admin: # 管理者の場合は管理者ダッシュボードへ
                return redirect(url_for('admin_dashboard'))
            else: # 営業職員の場合は営業職員ダッシュボードへ
                return redirect(url_for('sales_dashboard'))

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
            flash('ログインしました！', 'success') # 成功メッセージ
            
            # 初回ログインの場合はパスワードリセット画面へリダイレクト
            if user.is_first_login:
                return redirect(url_for('reset_password'))
            # 管理者の場合は管理者ダッシュボードへリダイレクト
            elif user.is_admin:
                return redirect(url_for('admin_dashboard'))
            # それ以外（営業職員）は営業職員ダッシュボードへリダイレクト
            else:
                return redirect(url_for('sales_dashboard'))
        else:
            # ログイン失敗メッセージ
            flash('メールアドレスまたはパスワードが間違っています。', 'danger')
    # GETリクエスト（ログイン画面表示）の場合の処理
    return render_template('login.html')

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

        try:
            # データベースに追加・コミット
            db.session.add(new_user)
            db.session.commit()

            flash(f'ユーザー登録が完了しました。初回ログイン時にパスワードを変更してください。', 'success')
            # 仮パスワードを登録成功画面に表示 (実際はメールで送信するが今回は画面表示で代替)
            return render_template('registration_success.html', email=email, temporary_password=temporary_password)
        except Exception as e:
            db.session.rollback() # エラー時はロールバック
            flash(f'ユーザー登録中にエラーが発生しました。もう一度お試しください。 ({e})', 'danger')
            # エラー時も入力値を保持してテンプレートを再表示
            return render_template('register.html', email=email, affiliation=affiliation, name=name)

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
    # ユーザーが見つからない場合
    if not user:
        flash('ユーザーが見つかりません。', 'danger')
        return redirect(url_for('login'))

    # 初回ログインではない場合、パスワード再設定は不要なのでダッシュボードへリダイレクト
    if not user.is_first_login:
        flash('パスワードは既に設定済みです。', 'info')
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

    # 重複しない都道府県リストを作成 (ソート済み)
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
    # ログインしていない、または管理者権限がない場合はアクセス拒否
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))
    
    # 事務職員（管理者）以外のユーザーを取得 (メールアドレス順)
    users = User.query.order_by(User.email).all() # 全てのユーザーを取得し、一覧で表示
    return render_template('admin_users.html', users=users)

# 事務職員によるユーザー編集ページ
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    # ログインしていない、または管理者権限がない場合はアクセス拒否
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id) # ユーザーIDでユーザーを取得 (見つからない場合は404)
    
    # ログイン中の事務職員が自分自身の管理者権限を変更できないようにする
    if user.id == session['user_id'] and user.is_admin:
        flash('ご自身の管理者権限は変更できません。', 'danger')
        return redirect(url_for('admin_users'))

    # POSTリクエスト（ユーザー編集フォーム送信）の場合の処理
    if request.method == 'POST':
        new_email = request.form['email'].strip() # 新しいメールアドレス
        new_name = request.form['name'].replace(' ', '').replace('　', '').strip() # 新しい名前 (スペース除去)
        new_affiliation = request.form['affiliation'].strip() # 新しい所属
        reset_password_flag = 'reset_password' in request.form # パスワードリセットチェックボックスがチェックされたか
        new_is_admin_status = 'is_admin' in request.form # 「このユーザーを事務職員にする」チェックボックスがチェックされたか

        # メールアドレスのドメイン検証
        if not new_email.endswith('@clp-ytmm.com'):
            flash('メールアドレスは "@clp-ytmm.com" ドメインである必要があります。', 'danger')
            return render_template('edit_user.html', user=user) # フォームを再表示

        # メールアドレス変更の場合、重複チェック
        if new_email != user.email and User.query.filter_by(email=new_email).first():
            flash('このメールアドレスは既に他のユーザーに登録されています。', 'danger')
            return render_template('edit_user.html', user=user) # フォームを再表示

        # ユーザー情報を更新
        user.email = new_email
        user.name = new_name
        user.affiliation = new_affiliation
        user.is_admin = new_is_admin_status # 管理者権限を更新
        
        # パスワードリセットが要求された場合
        if reset_password_flag:
            # 仮パスワードを生成し、is_first_loginをTrueに設定
            temporary_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(8))
            user.set_password(temporary_password)
            user.is_first_login = True
            flash(f'ユーザー情報を更新し、パスワードをリセットしました。新しい仮パスワード: {temporary_password} (初回ログイン時に変更が必要です)', 'success')
        else:
            flash('ユーザー情報が更新されました。', 'success')
        
        db.session.commit() # データベースにコミット
        return redirect(url_for('admin_users')) # ユーザー一覧ページへリダイレクト
    
    # GETリクエスト（ユーザー編集フォーム表示）の場合の処理
    return render_template('edit_user.html', user=user)

# 事務職員によるユーザー削除機能
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # ログインしていない、または管理者権限がない場合はアクセス拒否
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id) # ユーザーIDでユーザーを取得 (見つからない場合は404)
    if user.is_admin: # 管理者ユーザーは削除させない
        flash('管理者ユーザーは削除できません。', 'danger')
        return redirect(url_for('admin_users'))
    
    # ユーザーに関連するエリア割り当て (UserArea) と変更履歴 (AreaChangeLog) を削除
    UserArea.query.filter_by(user_id=user.id).delete()
    AreaChangeLog.query.filter_by(user_id=user.id).delete()
    
    db.session.delete(user) # ユーザーを削除
    db.session.commit() # データベースにコミット
    flash('ユーザーが正常に削除されました。', 'success')
    return redirect(url_for('admin_users')) # ユーザー一覧ページへリダイレクト


# 事務職員による市区町村データアップロードページを表示・処理
@app.route('/admin_upload_municipalities', methods=['GET', 'POST'])
def admin_upload_municipalities():
    # ログインしていない、または管理者権限がない場合はアクセス拒否
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
                # アップロードされたCSVファイルをpandasで読み込む
                df = None
                # local_gov_codeとpostal_codeを明示的に文字列として読み込む
                read_csv_params = {'dtype': {'地方公共団体コード': str, '郵便番号': str}} 
                
                # まずはutf-8で試行
                try:
                    # streamから直接バイトを読み込み、デコードしてからStringIOに渡す
                    file_content = file.stream.read().decode('utf-8')
                    df = pd.read_csv(io.StringIO(file_content), **read_csv_params)
                except UnicodeDecodeError:
                    # utf-8で失敗した場合、cp932 (Shift-JIS) で再試行
                    file.stream.seek(0) # ストリームの読み込み位置を最初に戻す
                    file_content = file.stream.read().decode('cp932')
                    df = pd.read_csv(io.StringIO(file_content), **read_csv_params)

                # 期待される列名
                expected_columns = ['郵便番号', '地方公共団体コード', '都道府県', '市区町村']
                # 列名のチェック
                if not all(col in df.columns for col in expected_columns):
                    flash(f'CSVファイルの列名が正しくありません。以下の列が必要です: {", ".join(expected_columns)}', 'danger')
                    return render_template('admin_upload_municipalities.html')

                # 既存の市区町村データを取得
                existing_municipalities = {m.local_gov_code: m for m in Municipality.query.all()}
                
                # アップロードされたデータの地方公共団体コードのセット
                uploaded_local_gov_codes = set(df['地方公共団体コード'].tolist())

                # 追加される市区町村の特定
                for index, row in df.iterrows():
                    local_gov_code = row['地方公共団体コード']
                    if local_gov_code not in existing_municipalities:
                        additions.append(Municipality(
                            postal_code=row['郵便番号'],
                            local_gov_code=local_gov_code,
                            prefecture=row['都道府県'],
                            city_town_village=row['市区町村']
                        ))
                
                # 更新される市区町村の特定
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
                            'old_city_town_village': new_data['市区町村'],
                            'new_city_town_village': new_data['市区町村']
                        }
                        
                        # 実際の値の比較
                        if str(existing_muni.postal_code) != str(new_data['郵便番号']) or \
                           existing_muni.prefecture != new_data['都道府県'] or \
                           existing_muni.city_town_village != new_data['市区町村']:
                            is_updated = True
                            
                        # 更新情報を追加 (変更がある場合のみ)
                        if is_updated:
                            updates.append(update_info)

                # 削除される市区町村の特定
                for local_gov_code, existing_muni in existing_municipalities.items():
                    if local_gov_code not in uploaded_local_gov_codes:
                        deletions.append(existing_muni)
                
                if not additions and not updates and not deletions:
                    flash('CSVファイルの内容は現在のデータと一致しています。変更はありませんでした。', 'info')

                # プレビューデータをセッションに保存して、次の確定処理で利用できるようにする
                session['municipality_additions'] = [m.to_dict() for m in additions] # to_dictは後で定義
                session['municipality_updates'] = updates
                session['municipality_deletions'] = [m.to_dict() for m in deletions] # to_dictは後で定義

            except Exception as e:
                flash(f'CSVファイルの読み込みまたは解析中にエラーが発生しました: {e}', 'danger')
                # エラー時もrender_templateを呼び出して、現在のテンプレートを再表示
                return render_template('admin_upload_municipalities.html')

    # Municipalityモデルにto_dictメソッドを追加 (セッション保存用)
    def municipality_to_dict(muni):
        return {
            'id': muni.id,
            'postal_code': muni.postal_code,
            'local_gov_code': muni.local_gov_code,
            'prefecture': muni.prefecture,
            'city_town_village': muni.city_town_village
        }
    
    # additions, updates, deletions がセッションにある場合はそれを使用 (POSTリクエスト後の再表示用)
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
    # ログインしていない、または管理者権限がない場合はアクセス拒否
    if 'user_id' not in session or not session.get('is_admin'):
        flash('管理者権限が必要です。', 'danger')
        return redirect(url_for('login'))
    
    try:
        # セッションからプレビューデータを取得
        additions_data = session.pop('municipality_additions', [])
        updates_data = session.pop('municipality_updates', [])
        deletions_data = session.pop('municipality_deletions', [])

        # 削除処理: 削除対象の市区町村IDリストを作成
        deletion_local_gov_codes = {d['local_gov_code'] for d in deletions_data}
        
        if deletion_local_gov_codes:
            # 削除される市区町村に関連するUserAreaとAreaChangeLogをまず削除
            # SQLAlchemyのサブクエリを使って効率的に削除
            municipalities_to_delete_ids = db.session.query(Municipality.id).filter(
                Municipality.local_gov_code.in_(deletion_local_gov_codes)
            ).subquery()

            # AreaChangeLogの削除
            AreaChangeLog.query.filter(
                AreaChangeLog.municipality_id.in_(municipalities_to_delete_ids)
            ).delete(synchronize_session=False)

            # UserAreaの削除
            UserArea.query.filter(
                UserArea.municipality_id.in_(municipalities_to_delete_ids)
            ).delete(synchronize_session=False)

            # 市区町村自体の削除
            Municipality.query.filter(
                Municipality.local_gov_code.in_(deletion_local_gov_codes)
            ).delete(synchronize_session=False)
            print(f"市区町村データ {deletion_local_gov_codes} を削除しました。関連するUserAreaとAreaChangeLogも削除されました。")


        # 追加処理
        for item_data in additions_data:
            new_muni = Municipality(
                postal_code=item_data['postal_code'],
                local_gov_code=item_data['local_gov_code'],
                prefecture=item_data['prefecture'],
                city_town_village=item_data['city_town_village']
            )
            db.session.add(new_muni)
            print(f"新規市区町村 {new_muni.city_town_village} を追加しました。")

        # 更新処理
        for item_data in updates_data:
            existing_muni = Municipality.query.filter_by(local_gov_code=item_data['local_gov_code']).first()
            if existing_muni:
                existing_muni.postal_code = item_data['new_postal_code']
                existing_muni.prefecture = item_data['new_prefecture']
                existing_muni.city_town_village = item_data['new_city_town_village']
                print(f"市区町村 {existing_muni.city_town_village} を更新しました。")
        
        db.session.commit() # 全ての変更をコミット
        flash('市区町村データが正常に更新されました！', 'success')

    except Exception as e:
        db.session.rollback() # エラー時はロールバック
        flash(f'市区町村データの更新中にエラーが発生しました: {e}', 'danger')
        print(f"市区町村データの更新エラー: {e}")

    return redirect(url_for('admin_dashboard'))


# トップページをログインページにリダイレクト
@app.route('/')
def index():
    return redirect(url_for('login'))


# --- アプリケーションの実行 ---
if __name__ == '__main__':
    # データベースの初期化とデータ投入
    init_db_and_data()
    
    app.run(debug=True)

