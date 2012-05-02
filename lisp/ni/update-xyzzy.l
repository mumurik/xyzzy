(require "ni/setup")

(provide "ni/update-xyzzy")
(in-package "netinst")

(defvar *latest-xyzzy-info-url*
  "https://raw.github.com/mumurik/xyzzy/master/latest-xyzzy-info.l"
  "最新版のxyzzyの配布の情報の入ったファイルへのURL。packages.lと同じフォーマットを想定。")

(defvar *installed-xyzzy-info-file*
  (merge-pathnames "installed-xyzzy-info.l" *base-directory*)
  "現在インストールされているxyzzyのpackages.l相当のファイルの保存されているパス。
初回インストール時は存在しないので注意。")

(defvar *latest-xyzzy-info-file*
  (merge-pathnames "latest-xyzzy-info.l" *base-directory*)
  "最新のpackages.l相当のファイルの保存されているパス。")

(defvar *xhr* nil)

#-multiple-frames
(defun safe-data-read (file)
  (when (file-exist-p file)
    (when (check-read-time-eval file)
      (ni-error "不正なファイルです: ~%~A" file))
    (data-read-from-file file)))

#+multiple-frames
(defun safe-data-read (file)
  (when (file-exist-p file)
    (handler-case
	(data-read-from-file file)
      (reader-error (c)
	(ni-error "不正なファイルです: ~%~A" file)))))

(defun load-installed-xyzzy-info ()
"インストールされてるxyzzyに関するsiteを返す。site-*で要素にはアクセスできる。
srcが入っている事は保障されない。"
  (safe-data-read *installed-xyzzy-info-file*))

(defun load-latest-xyzzy-info ()
"最新のxyzzyに関するsiteを返す。site-*で要素にはアクセスできる。
srcが入っている事は保障されない。"
  (safe-data-read *latest-xyzzy-info-file*))



(defun https-get-to-file (url file)
"urlの内容をfileにバイナリで保存。fileはフルパス
一旦メモリに全て読み込むので大きなファイルでは使わないでください。
httpsからhttpへのredirectを許容しています。
これはniの場合はhashを比較するので比較的安全ですが、それ以外の用途に使う場合は注意。"
  (unless *xhr*
    (setq *xhr* (ole-create-object "WinHttp.WinHttpRequest.5.1")))
  (when *https-proxy-url*
    (ole-method *xhr* 'SetProxy 2 *https-proxy-url*)) ;HTTPREQUEST_PROXYSETTING_PROXY 2
  (long-operation
    (ole-method *xhr* 'open "GET" url nil) ;; non-blocking and just sleep never change state. so use as blocking.
    (ole-putprop *xhr* 'Option t 6) ; enable redirect 6
    (ole-putprop *xhr* 'Option t 12) ;EnableHttpsToHttpRedirects 12
    (ole-method *xhr* 'setRequestHeader "If-Modified-Since" "Thu, 01 Jun 1970 00:00:00 GMT") ; to invalidate cash
    (ole-method *xhr* 'send)
    (if (not (eq (ole-method *xhr* 'status) 200))
	(progn
	  (message-box "アーカイブの取得に失敗しました")
	  ; for debug (setq *xhr* nil)
	  nil)
      (let ((dir (directory-namestring file))
	    (stream (ole-create-object "ADODB.Stream")))
	(unless (file-exist-p dir)
	  (create-directory dir))
	(ole-putprop stream 'Type 1)
	(ole-method stream 'Open)
	(ole-method stream 'Write (ole-method *xhr* 'responseBody))
	(ole-method stream 'SaveToFile file 2) ;; overwrite
	(ole-method stream 'Close)
	t))))
  
(defun update-latest-xyzzy-info ()
"最新版のpackages.l相当のファイルをダウンロード。"
  (https-get-to-file *latest-xyzzy-info-url* *latest-xyzzy-info-file*)
  t)

(defun newer-version-exist-p ()
"最新版とmd5が違ったら新しい版があるとみなす。もしローカルにmd5が無ければ新しい版があるとみなす。
初回インストール時にはmd5が無いのでいつもt。"
  (let ((installed (installed-xyzzy-app)))
    (if installed
	(not (equal (app-md5 (installed-xyzzy-app))
		    (app-md5 (latest-xyzzy-app))))
	t)))

(defun xyzzy-info-to-app (info)
"xyzzyに関するsiteからxyzzyのpackagesの要素を返す。一番目の要素と決め打ち"  
  (if info
      (car (site-apps info))))

(defun latest-xyzzy-app ()
  (xyzzy-info-to-app (load-latest-xyzzy-info)))

(defun installed-xyzzy-app ()
  (xyzzy-info-to-app (load-installed-xyzzy-info)))

(defun fetch-latest-xyzzy-archive (latestapp)
"最新のarchiveを取得してmd5をチェックし、一致したらtを返す。
install-app-fetchとほとんど同じだけど、過去のarchiveは既に削除済みなのが違う。"
  (let ((file (app-src-file latestapp)))
    (unless (https-get-to-file (app-src latestapp) file)
      (return-from fetch-latest-xyzzy-archive))
    (if (app-src-md5sum-check latestapp)
	t
      (progn
	(delete-file file)
	nil))))

(defun update-xyzzy ()
  (let ((latestapp (latest-xyzzy-app)))
    (unless (fetch-latest-xyzzy-archive latestapp)
      (return-from update-xyzzy))
    (extract-archive (app-src-file latestapp) (si:system-root))
    (delete-file (app-src-file latestapp)
    (copy-file *latest-xyzzy-info-file* *installed-xyzzy-info-file* :if-exists :overwrite) 
    (case (message-box "次回起動時にxyzzyは更新されます。今すぐ再起動しますか？" nil
		       '(:yes-no :question :button1))
      (:yes (ed:restart-for-update))
      (:no nil)))))
  


(defun editor::check-update()
  (interactive)
  (update-latest-xyzzy-info)
  (if (newer-version-exist-p)
      (case (message-box "新しいバージョンがありました。更新しますか？" nil
			 '(:yes-no :question :button1))
	(:yes (update-xyzzy))
	(:no (return-from check-update)))
    (progn
     (message-box "お使いのバージョンは最新バージョンです。")
      (return-from check-update))))



