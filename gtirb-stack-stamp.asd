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
(defsystem "gtirb-stack-stamp"
    :name "gtirb-stack-stamp"
    :author "GrammaTech"
    :licence "MIT"
    :description "Stack-stamp binary executable transformation over GTIRB"
    :long-description "Stack stamping is a binary hardening
transformation in which a random key is xor'd on the return address on
the top of the stack upon entry to any function.  This same key is
again xor'd against the top of the stack just before the function
returns.  This can help defeat return oriented programming (ROP)
attacks--especially when used as part of a moving target defense
system."
    :depends-on (:gtirb-stack-stamp/gtirb-stack-stamp)
    :class :package-inferred-system
    :defsystem-depends-on (:asdf-package-system)
    :perform
    (test-op (o c) (symbol-call :gtirb-stack-stamp '#:test)))
