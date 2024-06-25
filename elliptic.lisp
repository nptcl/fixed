(defpackage elliptic (:use common-lisp sha))
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
    #xD78B4BDC7F0DAF19F24F38C29373A2CCAD46157242A50F37809B1DA3412A12E79CCC9C81264CFE9AD080997058FB61C4243CC32DBAA156B9
    (#x79A70B2B70400553AE7C9DF416C792C61128751AC92969240C25A07D728BDC93E21F7787ED6972249DE732F38496CD11698713093E9C04FC
     #x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF80000000000000000000000000000000000000000000000000000001)
    #x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3
    #x04))

(defvar *elliptic-bit*)
(defvar *elliptic-p*)
(defvar *elliptic-a*)
(defvar *elliptic-b*)
(defvar *elliptic-d*)
(defvar *elliptic-g*)
(defvar *elliptic-n*)
(defvar *elliptic-h*)
(defvar *elliptic-o*)
(defvar *elliptic-valid*)
(defvar *elliptic-addition*)
(defvar *elliptic-doubling*)
(defvar *elliptic-make-private*)
(defvar *elliptic-make-public*)
(defvar *elliptic-encode*)
(defvar *elliptic-decode*)
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
(defun encode-weierstrass (v compress)
  (let ((x (point3-x v))
        (y (point3-y v))
        (z (point3-z v)))
    (cond ((zerop z) #x00)
          ((null compress)
           (logior (ash #x04 (* 256 2))
                   (ash x 256)
                   y))
          (t (logior
               (ash (if (logbitp 0 y) #x03 #x04) 256)
               x)))))

(defun encode-secp256k1 (v &optional (compress t))
  (encode-weierstrass v compress))

(defun encode-secp256r1 (v &optional (compress t))
  (encode-weierstrass v compress))

(defun encode-ed25519 (v)
  (let* ((a (affine v))
         (x (point2-x a))
         (y (point2-y a)))
    (when (logbitp 0 x)
      (setq y (logior y (ash 1 255))))
    y))

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

;;  ed25519
(defun decode-weierstrass (r)
  (error "TODO: ~A" r))

(defun decode-secp256k1 (r)
  (decode-weierstrass r))

(defun decode-secp256r1 (r)
  (decode-weierstrass r))

(defun decode-ed25519-x (y)
  (when (< y *elliptic-p*)
    (let* ((yy (* y y))
           (u1 (modp (1- yy)))
           (v1 (1+ (* *elliptic-d* yy)))
           (v2 (* v1 v1))
           (v3 (* v1 v2))
           (v4 (* v2 v2))
           (uv3 (* u1 v3))
           (p (/ (- *elliptic-p* 5) 8))
           (x (mulp uv3 (power-mod (* uv3 v4) p *elliptic-p*)))
           (v1x2 (mulp v1 x x)))
      (cond ((= v1x2 u1) x)
            ((= v1x2 (- *elliptic-p* u1))
             (mulp x (power-mod 2 (/ (1- *elliptic-p*) 4) *elliptic-p*)))))))

(defun decode-ed25519 (r)
  (let* ((y (ldb (byte 255 0) r))
         (x0 (ldb (byte 1 255) r))
         (x (decode-ed25519-x y)))
    (cond ((null x) nil)
          ((and (= x 0) (= x0 1)) nil)
          ((/= (logand x #x01) x0) (make-point4 (- *elliptic-p* x) y))
          (t (make-point4 x y)))))


;;  ed448
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

(defun decode-ed448 (r)
  (let* ((y (ldb (byte 455 0) r))
         (x0 (ldb (byte 1 455) r))
         (x (decode-ed448-x y)))
    (cond ((null x) nil)
          ((and (= x 0) (= x0 1)) nil)
          ((/= (logand x #x01) x0) (make-point3 (- *elliptic-p* x) y))
          (t (make-point3 x y)))))

(defun decode (r)
  (funcall *elliptic-decode* r))


;;
;;  private key
;;
(defun make-private-256bit (&optional (n 4))
  (let ((hash (make-sha256encode)))
    (dotimes (i n)
      (little-endian-sha256encode hash (random (ash 1 256)) 32))
    (vector-little-integer
      (calc-sha256encode hash))))

(defun make-private-secp256k1 ()
  (let ((x (modp (make-private-256bit))))
    (if (zerop x)
      (make-private-secp256k1)
      x)))

(defun make-private-secp256r1 ()
  (make-private-secp256k1))

(defun make-private-ed25519 ()
  (make-private-256bit))

(defun make-private-ed448 (&optional (n 4))
  (let ((hash (make-sha512encode)))
    (dotimes (i n)
      (little-endian-sha512encode hash (random (ash 1 512)) 64))
    (vector-little-integer
      (calc-sha512encode hash) :end 57)))

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
  (let ((hash (make-sha512encode)))
    (little-endian-sha512encode hash private 32)
    (let* ((v (calc-sha512encode hash))
           (a (vector-little-integer v :start 0 :end 32))
           (b (vector-little-integer v :start 32 :end 64)))
      (let ((v (ash 1 254)))
        (setq a (logand a (- v 8)))
        (setq a (logior a v)))
      (values a b))))

(defun make-public-ed25519 (private)
  (multiple
    (make-public-sign-ed25519 private)
    *elliptic-g*))

(defun make-public-sign-ed448 (private)
  (let ((hash (make-shake-256-encode)))
    (little-endian-sha3encode hash private 57)
    (let* ((v (result-sha3encode hash 114))
           (a (vector-little-integer v :start 0 :end 57))
           (b (vector-little-integer v :start 57 :end 114)))
      (let ((v (ash 1 (- 114 8 1))))
        (setq a (logand a (- v 4)))
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
(defun sign-sha-weierstrass (message)
  (let ((sha (make-sha256encode)))
    (read-sha256encode sha message)
    (vector-big-integer
      (calc-sha256encode sha))))

(defun sign-loop-weierstrass (private message)
  (let* ((k (make-private))
         (a (affine (make-public k)))
         (r (modn (point2-x a))))
    (unless (zerop r)
      (let* ((e (sign-sha-weierstrass message))
             (s (modn (* (inverse-n k) (+ e (* r private))))))
        (unless (zerop s)
          (values r s))))))

(defun sign-weierstrass (private message)
  (multiple-value-bind (r s) (sign-loop-weierstrass private message)
    (if r
      (values r s)
      (sign-weierstrass private message))))

(defun sign-secp256k1 (private message)
  (sign-weierstrass private message))

(defun sign-secp256r1 (private message)
  (sign-weierstrass private message))


;;  ed25519
(defun sha512-message-ed25519 (x y message)
  (let ((sha (make-sha512encode)))
    (when x
      (little-endian-sha512encode sha x 32))
    (when y
      (little-endian-sha512encode sha y 32))
    (read-sha512encode sha message)
    (modn (vector-little-integer
            (calc-sha512encode sha)))))

(defun sign-ed25519 (private message)
  (multiple-value-bind (a prefix) (make-public-sign-ed25519 private)
    (let* ((ag (multiple a *elliptic-g*))
           (ae (encode ag))
           (rp (sha512-message-ed25519 prefix nil message))
           (rg (multiple rp *elliptic-g*))
           (re (encode rg))
           (h (sha512-message-ed25519 re ae message))
           (s (modn (+ rp (* h a)))))
      (values re s))))


;;  ed448
(defun sha3-message-ed448 (x y message)
  (let ((sha (make-shake-256-encode)))
    (when x
      (little-endian-sha3encode sha x 57))
    (when y
      (little-endian-sha3encode sha y 57))
    (read-sha3encode sha message)
    (modn (vector-little-integer
            (result-sha3encode sha 114)))))

(defun sign-ed448 (private message)
  (multiple-value-bind (a prefix) (make-public-sign-ed448 private)
    (let* ((ag (multiple a *elliptic-g*))
           (ae (encode ag))
           (rp (sha3-message-ed448 prefix nil message))
           (rg (multiple rp *elliptic-g*))
           (re (encode rg))
           (h (sha3-message-ed448 re ae message))
           (s (modn (+ rp (* h a)))))
      (values re s))))

(defun sign (private message)
  (funcall *elliptic-sign* private message))


;;
;;  verify
;;

;;  secp256k1, secp256r1
(defun verify-weierstrass (public message r s)
  (and (<= 1 r (1- *elliptic-n*))
       (<= 1 s (1- *elliptic-n*))
       (let* ((e (sign-sha-weierstrass message))
              (s1 (inverse-n s))
              (u1 (modn (* e s1)))
              (u2 (modn (* r s1)))
              (rp (addition
                    (multiple u1 *elliptic-g*)
                    (multiple u2 public))))
         (unless (zerop (point3-z rp))
           (let* ((a (affine rp))
                  (v (modn (point2-x a))))
             (= v r))))))

(defun verify-secp256k1 (public message r s)
  (verify-weierstrass public message r s))

(defun verify-secp256r1 (public message r s)
  (verify-weierstrass public message r s))


;;  ed25519
(defun verify-sha-ed25519 (r public message)
  (let ((sha (make-sha512encode)))
    (little-endian-sha512encode sha r 32)
    (little-endian-sha512encode sha public 32)
    (read-sha512encode sha message)
    (modn (vector-little-integer
            (calc-sha512encode sha)))))

(defun verify-ed25519 (public message r s)
  (let ((ai (encode public))
        (rp (decode r)))
    (cond ((or (null rp)) (values nil :error))
          ((<= *elliptic-n* s) nil)
          (t (let* ((k (verify-sha-ed25519 r ai message))
                    (x (multiple s *elliptic-g*))
                    (y (addition rp (multiple k public))))
               (equal-point x y))))))


;;  ed448
(defun verify-sha-ed448 (r public message)
  (let ((sha (make-shake-256-encode)))
    (little-endian-sha3encode sha r 57)
    (little-endian-sha3encode sha public 57)
    (read-sha3encode sha message)
    (modn (vector-little-integer
            (result-sha3encode sha 114)))))

(defun verify-ed448 (public message r s)
  (let ((ai (encode public))
        (rp (decode r)))
    (cond ((or (null rp)) (values nil :error))
          ((<= *elliptic-n* s) nil)
          (t (let* ((k (verify-sha-ed448 r ai message))
                    (x (multiple s *elliptic-g*))
                    (y (addition rp (multiple k public))))
               (equal-point x y))))))

(defun verify (public message r s)
  (funcall *elliptic-verify* public message r s))


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
          (*elliptic-valid* #'valid-weierstrass))
     ,@body))

(defmacro with-elliptic-secp256k1 (&body body)
  (destructuring-bind (bit p a b (gx gy) n h) +elliptic-secp256k1+
    `(with-elliptic-weierstrass
       (,bit ,p ,gx ,gy ,n ,h)
       (let* ((*elliptic-a* ,a)
              (*elliptic-b* ,b)
              (*elliptic-addition* #'addition-secp256k1)
              (*elliptic-doubling* #'doubling-secp256k1)
              (*elliptic-make-private* #'make-private-secp256k1)
              (*elliptic-make-public* #'make-public-secp256k1)
              (*elliptic-encode* #'encode-secp256k1)
              (*elliptic-decode* #'decode-secp256k1)
              (*elliptic-sign* #'sign-secp256k1)
              (*elliptic-verify* #'verify-secp256k1))
         ,@body))))

(defmacro with-elliptic-secp256r1 (&body body)
  (destructuring-bind (bit p a b (gx gy) n h) +elliptic-secp256r1+
    `(with-elliptic-weierstrass
       (,bit ,p ,gx ,gy ,n ,h)
       (let* ((*elliptic-a* ,a)
              (*elliptic-b* ,b)
              (*elliptic-addition* #'addition-secp256r1)
              (*elliptic-doubling* #'doubling-secp256r1)
              (*elliptic-make-private* #'make-private-secp256r1)
              (*elliptic-make-public* #'make-public-secp256r1)
              (*elliptic-encode* #'encode-secp256r1)
              (*elliptic-decode* #'decode-secp256r1)
              (*elliptic-sign* #'sign-secp256r1)
              (*elliptic-verify* #'verify-secp256r1))
         ,@body))))

(defmacro with-elliptic-edwards ((bit p n h) &body body)
  `(let* ((*elliptic-bit* ,bit)
          (*elliptic-p* ,p)
          (*elliptic-n* ,n)
          (*elliptic-h* ,h))
     ,@body))

(defmacro with-elliptic-ed25519 (&body body)
  (destructuring-bind (bit p a d (gx gy) n h) +elliptic-ed25519+
    `(with-elliptic-edwards
       (,bit ,p ,n ,h)
       (let* ((*elliptic-a* ,a)
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
              (*elliptic-verify* #'verify-ed25519))
         ,@body))))

(defmacro with-elliptic-ed448 (&body body)
  (destructuring-bind (bit p a d (gx gy) n h) +elliptic-ed448+
    `(with-elliptic-edwards
       (,bit ,p ,n ,h)
       (let* ((*elliptic-a* ,a)
              (*elliptic-d* ,d)
              (*elliptic-g* (make-point3 ,gx ,gy))
              (*elliptic-o* (make-point3 0 1 1))
              (*elliptic-valid* #'valid-edwards)
              (*elliptic-addition* #'addition-ed448)
              (*elliptic-doubling* #'doubling-ed448)
              (*elliptic-make-private* #'make-private-ed448)
              (*elliptic-make-public* #'make-public-ed448)
              (*elliptic-encode* #'encode-ed448)
              (*elliptic-decode* #'decode-ed448)
              (*elliptic-sign* #'sign-ed448)
              (*elliptic-verify* #'verify-ed448))
         ,@body))))

