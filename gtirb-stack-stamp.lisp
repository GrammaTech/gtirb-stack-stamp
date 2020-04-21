;;; Copyright (C) 2020 GrammaTech, Inc.
;;;
;;; This code is licensed under the MIT license. See the LICENSE file in
;;; the project root for license terms.
;;;
;;; This project is sponsored by the Office of Naval Research, One Liberty
;;; Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
;;; N68335-17-C-0700.  The content of the information does not necessarily
;;; reflect the position or policy of the Government and no official
;;; endorsement should be inferred.
(defpackage :gtirb-stack-stamp/gtirb-stack-stamp
  (:nicknames :gtirb-stack-stamp)
  (:use :gt/full :gtirb :gtirb-functions :gtirb-capstone
        :stefil :command-line-arguments)
  (:shadowing-import-from :gt :size)
  (:import-from :cl-intbytes :int->octets :octets->uint)
  (:import-from :asdf/system :system-relative-pathname)
  (:shadow :version :architecture :mode :symbol)
  (:export :gtirb-stack-stamp))
(in-package :gtirb-stack-stamp/gtirb-stack-stamp)
(in-readtable :curry-compose-reader-macros)
(defmethod size ((obj gtirb-node)) (gtirb:size obj))


;;; Implementation
(defgeneric stack-stamp (object)
  (:documentation "Apply the stack-stamp transformation.")
  (:method ((obj gtirb))
    (set-syntax obj :syntax-att)
    (mapc #'stack-stamp (modules obj)))
  (:method ((obj module)) (mapc #'stack-stamp (functions obj)))
  (:method ((obj func))
    (unless (exits obj)
      (warn "Skipping function without exits: ~s" obj)
      (return-from stack-stamp))
    (unless (entries obj)
      (warn "Skipping function without entries: ~s" obj)
      (return-from stack-stamp))
    (let* ((key (int->octets (sxhash obj) 8))
           (stamp-bytes (asm obj (format nil "xorl $0x~x,(%rsp); ~
                                              xorl $0x~x,4(%rsp);"
                                         (octets->uint (subseq key 0 4) 4)
                                         (octets->uint (subseq key 4) 4)))))
      (mapc (lambda (entry-block) (setf (bytes entry-block 0 0) stamp-bytes))
            (entries obj))
      (mapc
       (lambda (ret-block)
         ;; Convert instruction index into byte index.
         (when-let* ((ins (instructions ret-block))
                     (ret-ins-pos (position-if [{eql :ret} #'mnemonic] ins))
                     (ret-byte-pos (reduce #'+ (subseq ins 0 ret-ins-pos)
                                           :key #'size)))
           (setf (bytes ret-block ret-byte-pos ret-byte-pos) stamp-bytes)))
       (returns obj)))))

(defmethod stack-stamp :around ((obj gtirb-node)) (call-next-method) obj)


;;;; Main test suite.
(defsuite test)
(in-suite test)

(defvar *hello*)

(defixture hello
  (:setup (setf *hello* (read-gtirb
                         (system-relative-pathname "gtirb-stack-stamp"
                                                   "tests/hello.v1.gtirb"))))
  (:teardown (setf *hello* nil)))

(defun drop-cfi (ir)
  (mapc (lambda (module)
          (setf (aux-data module)
                (remove-if [{string= "cfiDirectives"} #'car]
                           (aux-data module))))
        (modules ir))
  ir)

(deftest stack-stamp-hello ()
  (nest
   (with-fixture hello)
   (flet ((symbolic-expressions (it)
            (nest (mappend [#'hash-table-values #'symbolic-expressions])
                  (mappend #'byte-intervals) (mappend #'sections)
                  (modules it)))
          (interval-bytes (it)
            (nest (apply #'concatenate 'vector)
                  (mapcar #'bytes)
                  (mappend #'byte-intervals) (mappend #'sections)
                  (modules it)))
          (block-bytes (it)
            (nest (apply #'concatenate 'vector)
                  (mapcar #'bytes) (mappend #'blocks)
                  (mappend #'byte-intervals) (mappend #'sections)
                  (modules it)))))
   (let ((original-symbolic-expressions (symbolic-expressions *hello*))
         (original-interval-bytes (interval-bytes *hello*))
         (original-bytes (block-bytes *hello*)))
     (is (typep (stack-stamp *hello*) 'gtirb))
     (let ((new-symbolic-expressions (symbolic-expressions *hello*)))
       ;; Should not have fewer symbolic expressions when we're only
       ;; inserting (not removing) instructions (and therefore bytes).
       (is (= (length original-symbolic-expressions)
              (length new-symbolic-expressions)))
       ;; In fact we should have exactly the same instructions.
       (is (= (length original-symbolic-expressions)
              (length new-symbolic-expressions))))
     (let ((new-bytes (block-bytes *hello*)))
       ;; We should have more bytes (with the new stamping instructions).
       (is (< (length original-interval-bytes)
              (length (interval-bytes *hello*))))
       (is (< (length original-bytes) (length new-bytes)))))))


;;;; External command-line driver.
;;;
;;; Compile with the following command:
;;;   sbcl --eval '(ql:quickload :gtirb-stack-stamp)' \
;;;        --eval '(asdf:make :gtirb-stack-stamp :type :program :monolithic t)'
;;;
(define-command ss
    (input output
           &spec
           '((("help" #\h #\?) :type boolean :optional t
              :documentation "display help output")
             (("gtirb" #\g) :type boolean :optional t :initial-value nil
              :documentation "output binary gtirb (default)")
             (("asm" #\a) :type boolean :optional t :initial-value nil
              :documentation "output assembly text")
             (("binary" #\b) :type boolean :optional t :initial-value nil
              :documentation "output a binary executable"))
           &aux ir)
  "Apply \"stack stamp\" protections to a binary executable." ""
  (when help (show-help-for-stamp))
  (unless (or gtirb asm binary)
    (error "Must specify at least one output type: gtirb, asm, or binary."))
  (setf ir
        ;; If INPUT is a path that doesn't end in "gtirb" call ddisasm.
        (if (and (or (pathnamep input) (stringp input))
                 (not (string= "gtirb" (pathname-type input))))
            (with-temporary-file (:pathname temp :type "gtirb" :direction input)
              (wait-process
               (launch-program
                (list "ddisasm" (namestring input) "--ir" (namestring temp))
                :output *standard-output*
                :error-output *error-output*))
              (read-gtirb temp))
            ;; Otherwise we assume our input is already a GTIRB file.
            (read-gtirb input)))
  (setf ir (stack-stamp (drop-cfi ir)))
  (labels ((normalize-path (others extension)
             (let ((new (if others
                            (make-pathname :type extension :defaults output)
                            output)))
               (when (and (not (equalp new output)) (probe-file new))
                 (error "Output ~a already exists" (namestring new)))
               (namestring new)))
           (gtirb-path () (normalize-path (or asm binary) "gtirb"))
           (binary-path () (normalize-path (or asm gtirb) nil))
           (asm-path () (normalize-path (or gtirb binary) "s")))
    (with-temporary-file (:pathname temp :type "gtirb" :direction output)
      (write-gtirb ir temp)
      (when gtirb
        (wait-process
         (launch-program (list "cp" (namestring temp) (gtirb-path)))))
      (when (or asm binary)
        (wait-process
         (launch-program
          `("gtirb-pprinter" ,(namestring temp)
                             "--skip-section"".eh_frame"
                             ,@(when binary (list "--binary" (binary-path)))
                             ,@(when asm (list "--asm" (asm-path))))
          :output *standard-output*
          :error-output *error-output*))))))
