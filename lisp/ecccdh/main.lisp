(defpackage work
  (:use common-lisp))
(in-package work)

(defun read-list (file)
  (do (list) (nil)
    (let ((x (read-line file nil nil)))
      (unless x
        (return (nreverse list)))
      (push x list))))

(defun trim (x)
  (string-trim '(#\Space #\Tab #\Return #\Linefeed) x))

(defun remove-space (list)
  (mapcar #'trim list))

(defun remove-comment (list)
  (remove-if
    (lambda (x)
      (or (= (length x) 0)
          (char= (char x 0) #\#)))
    list))

(defun split-keyword (x)
  (cond ((string-equal x "COUNT") 'count)
        ((string-equal x "QCAVSx") 'q.x)
        ((string-equal x "QCAVSy") 'q.y)
        ((string-equal x "dIUT") 'p.k)
        ((string-equal x "QIUTx") 'p.x)
        ((string-equal x "QIUTy") 'p.y)
        ((string-equal x "ZIUT") 'r.x)
        (t (error "Invalid keyword: ~S." x))))

(defun split-equal (str)
  (let* ((x (position #\= str))
         (y (trim (subseq str 0 x)))
         (z (trim (subseq str (1+ x)))))
    (list (split-keyword y) z)))

(defun split-list (list)
  (mapcar #'split-equal list))

(defun change-value (list)
  (mapcar
    (lambda (line)
      (destructuring-bind (x y) line
        (case x
          (count (list x (parse-integer y)))
          (otherwise line))))
    list))

(defun group-count (args)
  (let (list child)
    (dolist (x args)
      (when (and (eq (car x) 'count) child)
        (push (nreverse child) list)
        (setq child nil))
      (push x child))
    (push (nreverse child) list)
    (nreverse list)))

(defun append-name (name list)
  (mapcar
    (lambda (x)
      (cons (list 'curve name) x))
    list))

(defun main-input (file name)
  (append-name
    name
    (group-count
      (change-value
        (split-list
          (remove-comment
            (remove-space
              (read-list file))))))))

(defun list-get (key list)
  (let ((x (find key list :key #'car)))
    (if x
      (cadr x)
      (error "Invalid key: ~S." key))))

(defun output-testcase (s x)
  (let* ((curve (list-get 'curve x))
         (count (list-get 'count x))
         (qx (list-get 'q.x x))
         (qy (list-get 'q.y x))
         (pk (list-get 'p.k x))
         (px (list-get 'p.x x))
         (py (list-get 'p.y x))
         (rx (list-get 'r.x x))
         (c (string-downcase curve)))
    (format s "(deftest ecccdh-~A.~A~%" c count)
    (format s "  (ecccdh-check-~A~%" c)
    (format s "    #x~A~%" pk)
    (format s "    #x~A~%" px)
    (format s "    #x~A~%" py)
    (format s "    #x~A~%" qx)
    (format s "    #x~A)~%" qy)
    (format s "  #x~A)~%" (string-upcase rx))))


(defun main-output (file list)
  (let ((*print-case* :downcase))
    (dolist (x list)
      (output-testcase file x)
      (fresh-line file)
      (terpri file))))

(defun main (name input output)
  (let (list)
    (with-open-file (file input)
      (setq list (main-input file name)))
    (with-open-file (file output :direction :output
                          :if-exists :supersede
                          :if-does-not-exist :create)
      (main-output file list))))

(main 'secp256r1 #p"p256.txt" "test-secp256r1.lisp")
(main 'secp384r1 #p"p384.txt" "test-secp384r1.lisp")
(main 'secp521r1 #p"p521.txt" "test-secp521r1.lisp")

