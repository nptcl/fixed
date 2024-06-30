(defpackage elliptic
  (:use common-lisp sha)
  (:export
    #:*elliptic-curve*
    #:*elliptic-bit*
    #:*elliptic-p*
    #:*elliptic-a*
    #:*elliptic-b*
    #:*elliptic-d*
    #:*elliptic-g*
    #:*elliptic-n*
    #:*elliptic-h*
    #:*elliptic-o*
    #:*elliptic-context*

    #:point2
    #:make-point2
    #:point2-x
    #:point2-y

    #:point3
    #:make-point3
    #:point3-x
    #:point3-y
    #:point3-z

    #:point4
    #:make-point4
    #:point4-x
    #:point4-y
    #:point4-z
    #:point4-xy

    #:power-mod
    #:inverse
    #:inverse-n
    #:affine
    #:equal-point
    #:valid
    #:neutral

    #:addition
    #:doubling
    #:multiple
    #:encode
    #:decode
    #:make-private
    #:make-public
    #:sign
    #:verify

    #:encode1-vector
    #:encode2-vector
    #:encode1-string
    #:encode2-string
    #:decode1-vector
    #:decode2-vector
    #:decode1-string
    #:decode2-string

    #:with-elliptic-secp256k1
    #:with-elliptic-secp256r1
    #:with-elliptic-ed25519
    #:with-elliptic-ed448
    ))
(in-package elliptic)

;;
;;  elliptic curve
;;
(defconstant +elliptic-secp256k1+
  '(256
    #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    #x0000000000000000000000000000000000000000000000000000000000000000
    #x0000000000000000000000000000000000000000000000000000000000000007
    (#x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
     #x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
    #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    #x01))

(defconstant +elliptic-secp256r1+
  '(256
    #xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    #xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    #x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    (#x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
     #x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
    #xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    #x01))

(defconstant +elliptic-ed25519+
  '(256
    #x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
    #x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC
    #x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3
    (#x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
     #x6666666666666666666666666666666666666666666666666666666666666658)
    #x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    #x08))

(defconstant +elliptic-ed448+
  '(448
    #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    #x01
    #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6756
    (#x4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E
     #x693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14)
    #x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3
    #x04))

(defvar *elliptic-curve*)
(defvar *elliptic-bit*)
(defvar *elliptic-p*)
(defvar *elliptic-a*)
(defvar *elliptic-b*)
(defvar *elliptic-d*)
(defvar *elliptic-g*)
(defvar *elliptic-n*)
(defvar *elliptic-h*)
(defvar *elliptic-o*)
(defvar *elliptic-context*)
(defvar *elliptic-valid*)
(defvar *elliptic-neutral*)
(defvar *elliptic-addition*)
(defvar *elliptic-doubling*)
(defvar *elliptic-make-private*)
(defvar *elliptic-make-public*)
(defvar *elliptic-encode*)
(defvar *elliptic-decode*)
(defvar *elliptic-encode1*)
(defvar *elliptic-encode2*)
(defvar *elliptic-decode1*)
(defvar *elliptic-decode2*)
(defvar *elliptic-sign*)
(defvar *elliptic-verify*)

(defun modp (x)
  (mod x *elliptic-p*))

(defun modn (x)
  (mod x *elliptic-n*))

(defun mulp (&rest args)
  (modp (apply #'* args)))

(defun power-mod (x y n &optional (r 1))
  (if (< 0 y)
    (power-mod
      (mod (* x x) n)
      (ash y -1)
      n
      (if (logbitp 0 y)
        (mod (* r x) n)
        r))
    r))


;;
;;  point
;;
(defstruct (point2 (:constructor empty-point2)) x y)
(defstruct (point3 (:constructor empty-point3) (:include point2)) z)
(defstruct (point4 (:constructor empty-point4) (:include point3)) xy)

(defun make-point2 (x y)
  (empty-point2 :x x :y y))

(defun make-point3 (x y &optional z)
  (empty-point3 :x x :y y :z (or z 1)))

(defun make-point4 (x y &optional z xy)
  (empty-point4 :x x :y y
                :z (or z 1)
                :xy (or xy (mulp x y))))


;;
;;  affine
;;
(defun inverse (x)
  (power-mod x (- *elliptic-p* 2) *elliptic-p*))

(defun inverse-n (x)
  (power-mod x (- *elliptic-n* 2) *elliptic-n*))

(defun affine (v)
  (let ((z (inverse (point3-z v))))
    (make-point2
      (mulp (point3-x v) z)
      (mulp (point3-y v) z))))

(defun equal-point (p q)
  (let ((pz (point3-z p))
        (qz (point3-z q)))
    (and (zerop (modp (- (* (point3-x p) qz) (* (point3-x q) pz))))
         (zerop (modp (- (* (point3-y p) qz) (* (point3-y q) pz)))))))

(defun equal-point-affine (x y)
  (let ((a (affine x))
        (b (affine y)))
    (and (eql (point2-x a) (point2-x b))
         (eql (point2-y a) (point2-y b)))))


;;
;;  valid
;;
(defun valid-weierstrass (v)
  (let* ((a (affine v))
         (x (point2-x a))
         (y (point2-y a)))
    (zerop
      (modp (- (* y y)
               (+ (* x x x) (* *elliptic-a* x) *elliptic-b*))))))

(defun valid-edwards (v)
  (let* ((a (affine v))
         (x (point2-x a))
         (y (point2-y a))
         (xx (* x x))
         (yy (* y y)))
    (zerop
      (modp (- (+ (* *elliptic-a* xx) yy)
               (+ 1 (* *elliptic-d* xx yy)))))))

(defun valid-point4 (v)
  (let* ((z (inverse (point4-z v)))
         (x (mulp (point4-x v) z))
         (y (mulp (point4-y v) z))
         (xy (mulp (point4-xy v) z)))
    (zerop
      (modp (- (* x y) xy)))))

(defun valid-ed25519 (v)
  (and (valid-edwards v)
       (valid-point4 v)))

(defun valid (v)
  (funcall *elliptic-valid* v))


;;
;;  neutral
;;
(defun neutral-weierstrass (v)
  (cond ((typep v 'point4) nil)
        ((typep v 'point3) (zerop (point3-z v)))
        ((typep v 'point2) (and (= (point2-x v) 0)
                                (= (point2-y v) 0)))))

(defun neutral-edwards (v)
  (when (or (typep v 'point4)
            (typep v 'point3))
    (setq v (affine v)))
  (and (= (point2-x v) 0)
       (= (point2-y v) 1)))

(defun neutral (v)
  (funcall *elliptic-neutral* v))


;;
;;  addition
;;
(defun addition-weierstrass (p1 p2)
  (let* ((x1 (point3-x p1))
         (y1 (point3-y p1))
         (z1 (point3-z p1))
         (x2 (point3-x p2))
         (y2 (point3-y p2))
         (z2 (point3-z p2))
         (u1 (* x1 z2))
         (u2 (* x2 z1))
         (s1 (* y1 z2))
         (s2 (* y2 z1))
         (zz (* z1 z2))
         (t1 (+ u1 u2))
         (t2 (* t1 t1))
         (m (+ s1 s2))
         (r (+ (- t2 (* u1 u2)) (* *elliptic-a* zz zz)))
         (f (* zz m))
         (k1 (* m f))
         (k2 (* k1 k1))
         (g1 (+ t1 k1))
         (g2 (- (* g1 g1) t2 k2))
         (w (- (* 2 r r) g2)))
    (make-point3
      (modp (* 2 f w))
      (modp (- (* r (- g2 (* 2 w))) (* 2 k2)))
      (modp (* 4 f f f)))))

(defun addition-secp256k1 (p1 p2)
  (cond ((zerop (point3-z p1)) p2)
        ((zerop (point3-z p2)) p1)
        (t (addition-weierstrass p1 p2))))

(defun addition-secp256r1 (p1 p2)
  (addition-secp256k1 p1 p2))

(defun addition-ed25519 (p1 p2)
  (let* ((x1 (point4-x p1))
         (y1 (point4-y p1))
         (z1 (point4-z p1))
         (t1 (point4-xy p1))
         (x2 (point4-x p2))
         (y2 (point4-y p2))
         (z2 (point4-z p2))
         (t2 (point4-xy p2))
         (a (* (- y1 x1) (- y2 x2)))
         (b (* (+ y1 x1) (+ y2 x2)))
         (c (* t1 2 *elliptic-d* t2))
         (d (* z1 2 z2))
         (e (- b a))
         (f (- d c))
         (g (+ d c))
         (h (+ b a)))
    (make-point4
      (modp (* e f))
      (modp (* g h))
      (modp (* f g))
      (modp (* e h)))))

(defun addition-ed448 (p1 p2)
  (let* ((x1 (point3-x p1))
         (y1 (point3-y p1))
         (z1 (point3-z p1))
         (x2 (point3-x p2))
         (y2 (point3-y p2))
         (z2 (point3-z p2))
         (a (* z1 z2))
         (b (* a a))
         (c (* x1 x2))
         (d (* y1 y2))
         (e (* *elliptic-d* c d))
         (f (- b e))
         (g (+ b e))
         (h (* (+ x1 y1) (+ x2 y2))))
    (make-point3
      (modp (* a f (- h c d)))
      (modp (* a g (- d c)))
      (modp (* f g)))))

(defun addition (r1 r2)
  (funcall *elliptic-addition* r1 r2))


;;
;;  doubling
;;
(defun doubling-secp256k1 (p1)
  (let* ((x1 (point3-x p1))
         (y1 (point3-y p1))
         (z1 (point3-z p1))
         (xx (* x1 x1))
         (zz (* z1 z1))
         (q (+ (* *elliptic-a* zz) (* 3 xx)))
         (s1 (* 2 y1 z1))
         (s2 (* s1 s1))
         (s3 (* s1 s2))
         (r1 (* y1 s1))
         (r2 (* r1 r1))
         (u2 (+ x1 r1))
         (u (- (* u2 u2) xx r2))
         (h (- (* q q) (* 2 u))))
    (make-point3
      (modp (* h s1))
      (modp (- (* q (- u h)) (* 2 r2)))
      (modp s3))))

(defun doubling-secp256r1 (p1)
  (doubling-secp256k1 p1))

(defun doubling-ed25519 (p1)
  (let* ((x1 (point4-x p1))
         (y1 (point4-y p1))
         (z1 (point4-z p1))
         (a (* x1 x1))
         (b (* y1 y1))
         (c (* 2 z1 z1))
         (h (+ a b))
         (d (+ x1 y1))
         (e (- h (* d d)))
         (g (- a b))
         (f (+ c g)))
    (make-point4
      (modp (* e f))
      (modp (* g h))
      (modp (* f g))
      (modp (* e h)))))

(defun doubling-ed448 (p1)
  (let* ((x1 (point3-x p1))
         (y1 (point3-y p1))
         (z1 (point3-z p1))
         (a (+ x1 y1))
         (b (* a a))
         (c (* x1 x1))
         (d (* y1 y1))
         (e (+ c d))
         (h (* z1 z1))
         (j (- e (* 2 h))))
    (make-point3
      (modp (* (- b e) j))
      (modp (* e (- c d)))
      (modp (* e j)))))

(defun doubling (r1)
  (funcall *elliptic-doubling* r1))


;;
;;  multiple
;;
(defun multiple (s p &optional (q *elliptic-o*))
  (if (< 0 s)
    (multiple
      (ash s -1)
      (doubling p)
      (if (logbitp 0 s)
        (addition q p)
        q))
    q))


;;
;;  integer <-> vector
;;
(defun integer-little-vector (v size)
  (let ((a (make-array size :element-type '(unsigned-byte 8))))
    (dotimes (i size)
      (setf (aref a i) (ldb (byte 8 (* i 8)) v)))
    a))

(defun vector-little-integer (v &key (start 0) end)
  (unless end
    (setq end (length v)))
  (let ((r 0) (k 0))
    (loop for i from start below end
          do
          (setq r (logior r (ash (aref v i) (* k 8))))
          (incf k 1))
    r))

(defun integer-big-vector (v size)
  (let ((a (make-array size :element-type '(unsigned-byte 8))))
    (dotimes (i size)
      (let ((k (- size i 1)))
        (setf (aref a i) (ldb (byte 8 (* k 8)) v))))
    a))

(defun vector-big-integer (v &key (start 0) end)
  (unless end
    (setq end (length v)))
  (let ((r 0) (k (- end start 1)))
    (loop for i from start below end
          do
          (setq r (logior r (ash (aref v i) (* k 8))))
          (decf k 1))
    r))


;;
;;  square root
;;
(defun square-root-mod-4 (a)
  (let* ((x (power-mod a (/ (+ *elliptic-p* 1) 4) *elliptic-p*))
         (x2 (mulp x x)))
    (if (= x2 a)
      x)))

(defun square-root-mod-8 (a)
  (let* ((x (power-mod a (/ (+ *elliptic-p* 3) 8) *elliptic-p*))
         (x2 (mulp x x)))
    (cond ((= x2 a) x)
          ((= x2 (- *elliptic-p* a))
           (mulp x (power-mod 2 (/ (- *elliptic-p* 1) 4) *elliptic-p*))))))


;;
;;  encode
;;

;;  secp256k1, secp256r1 -> vector
(defun encode-compress-secp256k1 (x y)
  (integer-big-vector
    (logior (ash (if (logbitp 0 y) #x03 #x02) 256) x)
    (1+ 32)))

(defun encode-uncompress-secp256k1 (x y)
  (integer-big-vector
    (logior (ash #x04 (* 256 2)) (ash x 256) y)
    (1+ 64)))

(defun encode-secp256k1 (v &optional (compress t))
  (let* ((a (affine v))
         (x (point2-x a))
         (y (point2-y a))
         (z (point3-z v)))
    (cond ((zerop z) (integer-big-vector #x00 1))
          (compress (encode-compress-secp256k1 x y))
          (t (encode-uncompress-secp256k1 x y)))))

(defun encode-secp256r1 (v &optional (compress t))
  (encode-secp256k1 v compress))

;;  ed25519 -> integer
(defun encode-ed25519 (v)
  (let* ((a (affine v))
         (x (point2-x a))
         (y (point2-y a)))
    (when (logbitp 0 x)
      (setq y (logior y (ash 1 255))))
    y))

;;  ed448 -> integer
(defun encode-ed448 (v)
  (let* ((a (affine v))
         (x (point2-x a))
         (y (point2-y a)))
    (when (logbitp 0 x)
      (setq y (logior y (ash 1 455))))
    y))

(defun encode (&rest args)
  (apply *elliptic-encode* args))


;;
;;  decode
;;

;;  secp256k1, secp256r1 <- vector
(defun decode-compress-secp256k1 (k y0)
  (let* ((x (vector-big-integer k :start 1 :end 33))
         (a (modp (+ (* x x x) (* *elliptic-a* x) *elliptic-b*)))
         (y (square-root-mod-4 a)))
    (when y
      (unless (= (logand y #x01) y0)
        (setq y (- *elliptic-p* y)))
      (make-point3 x y))))

(defun decode-uncompress-secp256k1 (k)
  (let ((p (make-point3
             (vector-big-integer k :start 1 :end 33)
             (vector-big-integer k :start 33 :end 65))))
    (when (valid p)
      p)))

(defun decode-secp256k1 (k)
  (case (aref k 0)
    (#x00 (make-point3 0 0 0))
    (#x02 (decode-compress-secp256k1 k 0))
    (#x03 (decode-compress-secp256k1 k 1))
    (#x04 (decode-uncompress-secp256k1 k))))

(defun decode-secp256r1 (k)
  (decode-secp256k1 k))

;;  ed25519 <- integer
(defun decode-ed25519-x (y)
  (when (< y *elliptic-p*)
    (let* ((yy (* y y))
           (u1 (modp (1- yy)))
           (v1 (1+ (* *elliptic-d* yy)))
           (v2 (* v1 v1))
           (v3 (* v1 v2))
           (v4 (* v2 v2))
           (u1v3 (* u1 v3))
           (p (/ (- *elliptic-p* 5) 8))
           (x (mulp u1v3 (power-mod (* u1v3 v4) p *elliptic-p*)))
           (v1x2 (mulp v1 x x)))
      (cond ((= v1x2 u1) x)
            ((= v1x2 (- *elliptic-p* u1))
             (mulp x (power-mod 2 (/ (1- *elliptic-p*) 4) *elliptic-p*)))))))

(defun decode-ed25519 (k)
  (let* ((y (ldb (byte 255 0) k))
         (x0 (ldb (byte 1 255) k))
         (x (decode-ed25519-x y)))
    (cond ((null x) nil)
          ((and (= x 0) (= x0 1)) nil)
          ((/= (logand x #x01) x0) (make-point4 (- *elliptic-p* x) y))
          (t (make-point4 x y)))))

;;  ed448 <- integer
(defun decode-ed448-x (y)
  (when (< y *elliptic-p*)
    (let* ((yy (* y y))
           (u1 (modp (1- yy)))
           (u2 (* u1 u1))
           (u3 (* u1 u2))
           (u5 (* u2 u3))
           (v1 (1- (* *elliptic-d* yy)))
           (v3 (* v1 v1 v1))
           (u3v1 (* u3 v1))
           (u5v3 (* u5 v3))
           (p (/ (- *elliptic-p* 3) 4))
           (x (mulp u3v1 (power-mod u5v3 p *elliptic-p*)))
           (v1x2 (mulp v1 x x)))
      (when (= v1x2 u1)
        x))))

(defun decode-ed448 (k)
  (let* ((y (ldb (byte 455 0) k))
         (x0 (ldb (byte 1 455) k))
         (x (decode-ed448-x y)))
    (cond ((null x) nil)
          ((and (= x 0) (= x0 1)) nil)
          ((/= (logand x #x01) x0) (make-point3 (- *elliptic-p* x) y))
          (t (make-point3 x y)))))

;;  decode
(defun decode (k)
  (funcall *elliptic-decode* k))


;;
;;  private key
;;
(defun make-private-256bit (&optional (n 4))
  (let ((sha (make-sha256encode)))
    (dotimes (i n)
      (little-endian-sha256encode sha (random (ash 1 256)) 32))
    (vector-little-integer
      (calc-sha256encode sha))))

(defun make-private-secp256k1 ()
  (let ((x (modn (make-private-256bit))))
    (if (zerop x)
      (make-private-secp256k1)
      x)))

(defun make-private-secp256r1 ()
  (make-private-secp256k1))

(defun make-private-ed25519 ()
  (make-private-256bit))

(defun make-private-ed448 (&optional (n 4))
  (let ((sha (make-sha512encode)))
    (dotimes (i n)
      (little-endian-sha512encode sha (random (ash 1 512)) 64))
    (vector-little-integer
      (calc-sha512encode sha) :end 57)))

(defun make-private ()
  (funcall *elliptic-make-private*))


;;
;;  public key
;;
(defun make-public-secp256k1 (private)
  (multiple private *elliptic-g*))

(defun make-public-secp256r1 (private)
  (multiple private *elliptic-g*))

(defun make-public-sign-ed25519 (private)
  (let ((sha (make-sha512encode)))
    (little-endian-sha512encode sha private 32)
    (let* ((v (calc-sha512encode sha))
           (a (vector-little-integer v :start 0 :end 32))
           (b (vector-little-integer v :start 32 :end 64)))
      (let ((v (ash 1 254)))
        (setq a (logand a (- v 8)))  ;; cofactor
        (setq a (logior a v)))
      (values a b))))

(defun make-public-ed25519 (private)
  (multiple
    (make-public-sign-ed25519 private)
    *elliptic-g*))

(defun make-public-sign-ed448 (private)
  (let ((sha (make-shake-256-encode)))
    (little-endian-sha3encode sha private 57)
    (let* ((v (result-sha3encode sha 114))
           (a (vector-little-integer v :start 0 :end 57))
           (b (vector-little-integer v :start 57 :end 114)))
      (let ((v (ash 1 447)))
        (setq a (logand a (- v 4)))  ;; cofactor
        (setq a (logior a v)))
      (values a b))))

(defun make-public-ed448 (private)
  (multiple
    (make-public-sign-ed448 private)
    *elliptic-g*))

(defun make-public (private)
  (funcall *elliptic-make-public* private))


;;
;;  sign
;;

;;  secp256k1, secp256r1
(defun sign-sha-secp256k1 (message)
  (let ((sha (make-sha256encode)))
    (read-sha256encode sha message)
    (vector-big-integer
      (calc-sha256encode sha))))

(defun sign-loop-secp256k1 (private message)
  (let* ((k (make-private))
         (b (affine (make-public k)))
         (r (modn (point2-x b))))
    (unless (zerop r)
      (let* ((e (sign-sha-secp256k1 message))
             (s (modn (* (inverse-n k) (+ e (* r private))))))
        (unless (zerop s)
          (values r s))))))

(defun sign-secp256k1 (private message)
  (multiple-value-bind (r s) (sign-loop-secp256k1 private message)
    (if r
      (values r s)
      (sign-secp256k1 private message))))

(defun sign-secp256r1 (private message)
  (sign-secp256k1 private message))

;;  ed25519
(defun sign-sha-ed25519 (x y message)
  (let ((sha (make-sha512encode)))
    (when x (little-endian-sha512encode sha x 32))
    (when y (little-endian-sha512encode sha y 32))
    (read-sha512encode sha message)
    (modn (vector-little-integer
            (calc-sha512encode sha)))))

(defun sign-ed25519 (private message)
  (multiple-value-bind (u v) (make-public-sign-ed25519 private)
    (let* ((a (encode (multiple u *elliptic-g*)))
           (w (sign-sha-ed25519 v nil message))
           (r (encode (multiple w *elliptic-g*)))
           (k (sign-sha-ed25519 r a message))
           (s (modn (+ w (* k u)))))
      (values r s))))

;;  ed448
(defun sign-sha-ed448 (x y message &optional (sha1 0) (sha2 *elliptic-context*))
  (let ((sha (make-shake-256-encode)))
    (read-sha3encode sha (map 'vector #'char-code "SigEd448"))
    (byte-sha3encode sha sha1)
    (byte-sha3encode sha (length sha2))
    (read-sha3encode sha sha2)
    (when x (little-endian-sha3encode sha x 57))
    (when y (little-endian-sha3encode sha y 57))
    (read-sha3encode sha message)
    (modn (vector-little-integer
            (result-sha3encode sha 114)))))

(defun sign-ed448 (private message)
  (multiple-value-bind (u v) (make-public-sign-ed448 private)
    (let* ((a (encode (multiple u *elliptic-g*)))
           (w (sign-sha-ed448 v nil message))
           (r (encode (multiple w *elliptic-g*)))
           (k (sign-sha-ed448 r a message))
           (s (modn (+ w (* k u)))))
      (values r s))))

;;  sign
(defun sign (private message)
  (funcall *elliptic-sign* private message))


;;
;;  verify
;;

;;  secp256k1, secp256r1
(defun verify-secp256k1 (public message r s)
  (and (<= 1 r (1- *elliptic-n*))
       (<= 1 s (1- *elliptic-n*))
       (let* ((e (sign-sha-secp256k1 message))
              (s1 (inverse-n s))
              (u1 (modn (* e s1)))
              (u2 (modn (* r s1)))
              (p (addition
                   (multiple u1 *elliptic-g*)
                   (multiple u2 public))))
         (unless (zerop (point3-z p))
           (let* ((a (affine p))
                  (v (modn (point2-x a))))
             (= v r))))))

(defun verify-secp256r1 (public message r s)
  (verify-secp256k1 public message r s))

;;  ed25519
(defun verify-ed25519 (public message r s)
  (let ((a (encode public))
        (p (decode r)))
    (cond ((or (null p)) (values nil :error))
          ((<= *elliptic-n* s) nil)
          (t (let* ((k (sign-sha-ed25519 r a message))
                    (x (multiple s *elliptic-g*))
                    (y (addition p (multiple k public))))
               (equal-point x y))))))

;;  ed448
(defun verify-ed448 (public message r s)
  (let ((a (encode public))
        (p (decode r)))
    (cond ((or (null p)) (values nil :error))
          ((<= *elliptic-n* s) nil)
          (t (let* ((k (sign-sha-ed448 r a message))
                    (x (multiple s *elliptic-g*))
                    (y (addition p (multiple k public))))
               (equal-point x y))))))

;;  verify
(defun verify (public message r s)
  (funcall *elliptic-verify* public message r s))


;;
;;  encode / decode
;;
(defun encode1-secp256k1 (v)
  (integer-big-vector v 32))

(defun encode1-secp256r1 (v)
  (integer-big-vector v 32))

(defun encode1-ed25519 (v)
  (integer-little-vector v 32))

(defun encode1-ed448 (v)
  (integer-little-vector v 57))

(defun encode2-secp256k1 (&rest args)
  (apply #'encode-secp256k1 args))

(defun encode2-secp256r1 (&rest args)
  (apply #'encode-secp256r1 args))

(defun encode2-ed25519 (v)
  (integer-little-vector (encode-ed25519 v) 32))

(defun encode2-ed448 (v)
  (integer-little-vector (encode-ed448 v) 57))

(defun decode1-secp256k1 (v)
  (when (= (length v) 32)
    (vector-big-integer v)))

(defun decode1-secp256r1 (v)
  (when (= (length v) 32)
    (vector-big-integer v)))

(defun decode1-ed25519 (v)
  (when (= (length v) 32)
    (vector-little-integer v)))

(defun decode1-ed448 (v)
  (when (= (length v) 57)
    (vector-little-integer v)))

(defun decode2-secp256k1 (v)
  (let ((n (length v)))
    (when (or (= n 1) (= n 33) (= n 65))
      (decode-secp256k1 v))))

(defun decode2-secp256r1 (v)
  (let ((n (length v)))
    (when (or (= n 1) (= n 33) (= n 65))
      (decode-secp256r1 v))))

(defun decode2-ed25519 (v)
  (when (= (length v) 32)
    (decode-ed25519
      (vector-little-integer v))))

(defun decode2-ed448 (v)
  (when (= (length v) 57)
    (decode-ed448
      (vector-little-integer v))))


;;  interface
(defun encode1-vector (v)
  (funcall *elliptic-encode1* v))

(defun encode2-vector (&rest args)
  (apply *elliptic-encode2* args))

(defun encode-hexadecimal (x s)
  (format s "~2,'0X" x))

(defun encode-string (v)
  (when v
    (with-output-to-string (s)
      (map nil (lambda (x) (encode-hexadecimal x s)) v))))

(defun encode1-string (v)
  (encode-string
    (encode1-vector v)))

(defun encode2-string (&rest args)
  (encode-string
    (apply #'encode2-vector args)))

(defun decode1-vector (v)
  (when v
    (funcall *elliptic-decode1* v)))

(defun decode2-vector (v)
  (when v
    (funcall *elliptic-decode2* v)))

(defun decode-string (str)
  (multiple-value-bind (len2 zero) (truncate (length str) 2)
    (when (zerop zero)
      (let ((r (make-array len2 :element-type '(unsigned-byte 8)))
            invalid)
        (dotimes (i len2)
          (let* ((i2 (* i 2))
                 (hex (subseq str i2 (+ i2 2)))
                 (value (parse-integer hex :junk-allowed t :radix 16)))
            (if value
              (setf (aref r i) value)
              (setq invalid t))))
        (unless invalid
          r)))))

(defun decode1-string (v)
  (decode1-vector
    (decode-string v)))

(defun decode2-string (v)
  (decode2-vector
    (decode-string v)))


;;
;;  Curve
;;
(defmacro with-elliptic-weierstrass ((bit p gx gy n h) &body body)
  `(let* ((*elliptic-bit* ,bit)
          (*elliptic-p* ,p)
          (*elliptic-g* (make-point3 ,gx ,gy))
          (*elliptic-n* ,n)
          (*elliptic-h* ,h)
          (*elliptic-o* (make-point3 0 0 0))
          (*elliptic-valid* #'valid-weierstrass)
          (*elliptic-neutral* #'neutral-weierstrass))
     ,@body))

(defmacro with-elliptic-secp256k1 (&body body)
  (destructuring-bind (bit p a b (gx gy) n h) +elliptic-secp256k1+
    `(with-elliptic-weierstrass
       (,bit ,p ,gx ,gy ,n ,h)
       (let* ((*elliptic-curve* :secp256k1)
              (*elliptic-a* ,a)
              (*elliptic-b* ,b)
              (*elliptic-addition* #'addition-secp256k1)
              (*elliptic-doubling* #'doubling-secp256k1)
              (*elliptic-make-private* #'make-private-secp256k1)
              (*elliptic-make-public* #'make-public-secp256k1)
              (*elliptic-encode* #'encode-secp256k1)
              (*elliptic-decode* #'decode-secp256k1)
              (*elliptic-sign* #'sign-secp256k1)
              (*elliptic-verify* #'verify-secp256k1)
              (*elliptic-encode1* #'encode1-secp256k1)
              (*elliptic-encode2* #'encode2-secp256k1)
              (*elliptic-decode1* #'decode1-secp256k1)
              (*elliptic-decode2* #'decode2-secp256k1))
         ,@body))))

(defmacro with-elliptic-secp256r1 (&body body)
  (destructuring-bind (bit p a b (gx gy) n h) +elliptic-secp256r1+
    `(with-elliptic-weierstrass
       (,bit ,p ,gx ,gy ,n ,h)
       (let* ((*elliptic-curve* :secp256r1)
              (*elliptic-a* ,a)
              (*elliptic-b* ,b)
              (*elliptic-addition* #'addition-secp256r1)
              (*elliptic-doubling* #'doubling-secp256r1)
              (*elliptic-make-private* #'make-private-secp256r1)
              (*elliptic-make-public* #'make-public-secp256r1)
              (*elliptic-encode* #'encode-secp256r1)
              (*elliptic-decode* #'decode-secp256r1)
              (*elliptic-sign* #'sign-secp256r1)
              (*elliptic-verify* #'verify-secp256r1)
              (*elliptic-encode1* #'encode1-secp256r1)
              (*elliptic-encode2* #'encode2-secp256r1)
              (*elliptic-decode1* #'decode1-secp256r1)
              (*elliptic-decode2* #'decode2-secp256r1))
         ,@body))))

(defmacro with-elliptic-edwards ((bit p n h) &body body)
  `(let* ((*elliptic-bit* ,bit)
          (*elliptic-p* ,p)
          (*elliptic-n* ,n)
          (*elliptic-h* ,h)
          (*elliptic-neutral* #'neutral-edwards))
     ,@body))

(defmacro with-elliptic-ed25519 (&body body)
  (destructuring-bind (bit p a d (gx gy) n h) +elliptic-ed25519+
    `(with-elliptic-edwards
       (,bit ,p ,n ,h)
       (let* ((*elliptic-curve* :ed25519)
              (*elliptic-a* ,a)
              (*elliptic-d* ,d)
              (*elliptic-g* (make-point4 ,gx ,gy))
              (*elliptic-o* (make-point4 0 1 1 0))
              (*elliptic-valid* #'valid-ed25519)
              (*elliptic-addition* #'addition-ed25519)
              (*elliptic-doubling* #'doubling-ed25519)
              (*elliptic-make-private* #'make-private-ed25519)
              (*elliptic-make-public* #'make-public-ed25519)
              (*elliptic-encode* #'encode-ed25519)
              (*elliptic-decode* #'decode-ed25519)
              (*elliptic-sign* #'sign-ed25519)
              (*elliptic-verify* #'verify-ed25519)
              (*elliptic-encode1* #'encode1-ed25519)
              (*elliptic-encode2* #'encode2-ed25519)
              (*elliptic-decode1* #'decode1-ed25519)
              (*elliptic-decode2* #'decode2-ed25519))
         ,@body))))

(defmacro with-elliptic-ed448 (&body body)
  (destructuring-bind (bit p a d (gx gy) n h) +elliptic-ed448+
    `(with-elliptic-edwards
       (,bit ,p ,n ,h)
       (let* ((*elliptic-curve* :ed448)
              (*elliptic-a* ,a)
              (*elliptic-d* ,d)
              (*elliptic-g* (make-point3 ,gx ,gy))
              (*elliptic-o* (make-point3 0 1 1))
              (*elliptic-context* #())
              (*elliptic-valid* #'valid-edwards)
              (*elliptic-addition* #'addition-ed448)
              (*elliptic-doubling* #'doubling-ed448)
              (*elliptic-make-private* #'make-private-ed448)
              (*elliptic-make-public* #'make-public-ed448)
              (*elliptic-encode* #'encode-ed448)
              (*elliptic-decode* #'decode-ed448)
              (*elliptic-sign* #'sign-ed448)
              (*elliptic-verify* #'verify-ed448)
              (*elliptic-encode1* #'encode1-ed448)
              (*elliptic-encode2* #'encode2-ed448)
              (*elliptic-decode1* #'decode1-ed448)
              (*elliptic-decode2* #'decode2-ed448))
         ,@body))))


;;
;;  (defun verify-string (public message r s)
;;    (verify (decode2-string public)
;;            (map 'vector #'char-code message)
;;            (decode1-string r)
;;            (decode1-string s)))
;;
;;  (with-elliptic-secp256k1
;;    (verify-string
;;      "03FEEF09658067CFBE3BE8685DDCE8E9C03B4A397ADC4A0255CE0B29FC63BCDC9C"
;;      "Hello"
;;      "7C7EDD22B0AED24D1B4A3826E228CE52EC897D52826D5912459238FC36008B86"
;;      "38C86C613A977CD5D1E024380FB56CDB924B0D972E903AB740F4E7F3A90F62BC"))
;;  (with-elliptic-secp256r1
;;    (verify-string
;;      "03CD92CF7B1C9CE9858383806B8540D72FB022BE577E21DE02B8EAA27371DB7AF2"
;;      "Hello"
;;      "FF6331919D62BFF9236113998250AB9079AA81C83085A27CC38A2CC0EEDDD98D"
;;      "1A374ADE37A61F6014C29C723C425BB3E6B519D517E16F66A46869F8EC535F89"))
;;  (with-elliptic-ed25519
;;    (verify-string
;;      "75AB16F53A060E7AF9A4B8ECEA3D4DEF058AED2C626FEC96D5505C4A7D922960"
;;      "Hello"
;;      "285D61D0DAC982F09365DA699DFD10A7B1B3A4D29A8468655A71F49965D4CEE1"
;;      "A58118E7ECAE263034F4BA7EB57BEE8D639C9BAF5BDE6BE97F2F864B3A1A7606"))
;;  (with-elliptic-ed448
;;    (verify-string
;;      "99AFC3768EE41B96F208EBAF8627908690DC6A5AC64659F93D0A46C2092B61E84AD14DD03F7B3F146799C29F65682126D517B7E1EA57716E00"
;;      "Hello"
;;      "DC38653AAD2F456132602EBC47571DABB56C36BA35D6965F820AFFB0FBE478439C7CF1D9EE7033792A23E80811CFAB07DC2B71DDEF526F6700"
;;      "0E11296ECFACEA4E5E9B795AC4048D711636BE468A99639F953ED1E948A6351F51DE0AE167EB268012E9712F7D6ADD97E80BB36E291C2A2D00"))
;;

