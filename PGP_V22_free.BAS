Rem BasicCard (7.5_D) Source Code for OpenPGP Card
Rem Version 2.2
Rem Copyright (C)2018 Achim Pietig (openpgp@pietig.com)
Rem All commands, functions and DOs from the V2.2 specification, except Secure Messaging

' License:
'
' Redistribution and use in source and binary forms, with or without
' modification, are permitted provided that the following conditions
' are met:
'
' 1. Redistributions of source code must retain the above copyright
'    notice, this list of conditions and the following disclaimer.
' 2. Redistributions in binary form must reproduce the above copyright
'    notice, this list of conditions and the following disclaimer in the
'    documentation and/or other materials provided with the distribution.
' 3. The name of the author may not be used to endorse or promote products
'    derived from this software without specific prior written permission.
'
' Changes to this license can be made only by the copyright author with
' explicit written consent.
'
' THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
' IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
' OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
' IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
' INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
' NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
' DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
' THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
' (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
' THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

' REMARKS:
'
' This source can be compiled with the free BasicCard development kit from Zeitcontrol (www.basiccard.com).
' Blank cards in small volumes can be ordered there also.
'
' This source code has the same functionality than the sold version, but has no internal security hardenings. All lines with these additional checks are deleted, the remaining code is identical.
' Smart card programming differs from normal source code for e. g. PCs, because there are several hardware attacks against the content of a smart card (e. g. Power fail attack, DPA, DFA).
' The knowledge/code to protect a card against these attacks was given to me under NDA.
' An example of an expired patent can be found in the VERIFY command.
'
' The pre-defined AID in the source generates test cards with a constant serial number. If a user needs different serials, the AID in the source should be aligned.
' Users/vendors without manufacturer registration from FSFE/Gnupg e. V. shall not change the manufacturer ID in the source and are only allowed to produce test cards (manufacturer ID = 0000 or FFFF).
' Registered manufactures have special functions on their production machines to provide unique serial numbers to OpenPGP smart cards.

'
'DECLARATIONS:
'
DefByte A-Z
Option Explicit
Option Base 1
#Files 0    'No file system
#Include RSA.DEF
#Include AES.DEF
#Include MISC.DEF
#Include Tlv12.DEF

' Unused algorithms are switched off
Disable Encryption &H21,&H22,&H23,&H24,&H25,&H32,&H41,&H42,&H42,&H81,&H82,&H83

' Function based on Tlv12.DEF to extract part of keys from key strings
' Tlv12.DEF is a special LIB (not compatible with the actual Tlv.DEF) and is provided with the source.
' It must be copied in the corresponding LIB-folder of the BasicCard development software.
Declare Function GetAsnInteger(Data$, Index%) As String

' Reset of the whole application with TERMINATE and ACTIVATE
Declare Sub CardInit()

'
' ATR - Definition (T=1, 115200 Baud, 10 Historicals)
' Historicals = Card service data + Card capatibilities + Status
#Pragma ATR(T=1, FI=1, DI=8, HB=Chr$(0)+Chr$(&H31)+Chr$(&HC5)+Chr$(&H73)+Chr$(&HC0)+Chr$(&H01)+Chr$(&H40)+Chr$(0)+Chr$(&H90)+Chr$(0))

' Extended Length enabled
#Pragma Enable Long Command

'
'   Variables and constants
'
' Inital value for error counters
Const FBZDef = 3
'Default RSA-Length
Const DefRSALength = 2048
' Maximum length of passwords
Const MaxPWLength = 32

' EEPROM:
' AID (all cards are test cards with serial number set to zero)
Eeprom AID As String*16 = &HD2,&H76,&H00,&H01,&H24,&H01,&H02,&H02,&H00,&H00,&H00,&H00,&H00,&H00,&H00,&H00
' Sequence counter for signatures
Eeprom Counter As String*3 = String$(3, 0)
' Applikation passwords (1 and 3) with default values
Eeprom EPW$(2) = "123456", "12345678"
' Error counter for Applikation PWs
Eeprom PWFBZ(2) = FBZDef, FBZDef
' Resetting code
Eeprom PWRC$ = ""
' Error counter for Resetting Code
Eeprom RCFBZ = 0

' Actual RSA length
Eeprom ActRSALenSig As Integer = DefRSALength
Eeprom ActRSALenDec As Integer = DefRSALength
Eeprom ActRSALenAut As Integer = DefRSALength

' Static Data Objecs (DO)
Eeprom ExtCap As String*10 = &H7C,&H00,&H08,&H00,&H08,&H00,&H08,&H00,&H08,&H00
Eeprom PWStatus As String*4 = &H00,MaxPWLength,MaxPWLength,MaxPWLength  'Whithout error counter
Eeprom Historicals As String*10 = &H00,&H31,&HC5,&H73,&HC0,&H01,&H40,&H05,&H90,&H00 ' Application with Life Cycle Status (LCS)

' Changeable DOs (PUT DATA)
Eeprom LCS As String*1 At Historicals + 7
Eeprom PW1once As String*1 At PWStatus
Eeprom AlgAttrSig As String*6 = &H01,(DefRSALength / 256),(DefRSALength Mod 256),&H00,&H20,&H00
Eeprom AlgAttrDec As String*6 = &H01,(DefRSALength / 256),(DefRSALength Mod 256),&H00,&H20,&H00
Eeprom AlgAttrAut As String*6 = &H01,(DefRSALength / 256),(DefRSALength Mod 256),&H00,&H20,&H00
Eeprom Sex As String*1 = &H39
Eeprom FPSig As String*20 = String$(20,0)
Eeprom FPDec As String*20 = String$(20,0)
Eeprom FPAut As String*20 = String$(20,0)
Eeprom CAFP(3) As String*20 = String$(20,0), String$(20,0), String$(20,0) 
Eeprom GenDateSig As String*4 = String$(4,0)
Eeprom GenDateDec As String*4 = String$(4,0)
Eeprom GenDateAut As String*4 = String$(4,0)
Eeprom LoginData$ = ""
Eeprom URL$ = ""
Eeprom UName$ = ""
Eeprom LangPref$ = "de"
Eeprom AESKeyDec$ = ""
Eeprom SigK$ = ""
Eeprom DecK$ = ""
Eeprom AutK$ = ""
Eeprom PubSigK$ = ""
Eeprom PubDecK$ = ""
Eeprom PubAutK$ = ""
Eeprom Zertifikat$ = ""
Eeprom PU1$ = ""
Eeprom PU2$ = ""
Eeprom PU3$ = ""
Eeprom PU4$ = ""

' RAM:
' Flag for application selection
Public AppSel = 0
' Flags for correct password check (1-3)
Public PWchk(3) = 0,0,0

' FUNCTIONS:
'
' Application reset
Sub CardInit()
    ' Sequence counter for signatures
    Counter = String$(3, 0)
    ' Keys
    AESKeyDec$ = ""
    SigK$ = ""
    DecK$ = ""
    AutK$ = ""
    PubSigK$ = ""
    PubDecK$ = ""
    PubAutK$ = ""
    ' Actual RSA length
    ActRSALenSig = DefRSALength
    ActRSALenDec = DefRSALength
    ActRSALenAut = DefRSALength
    ' Changeable DOs
    PW1once = Chr$(0)
    AlgAttrSig = Chr$(&H01) + Chr$(DefRSALength / 256) + Chr$(DefRSALength Mod 256) + Chr$(&H00) + Chr$(&H20) + Chr$(&H00)
    AlgAttrDec = Chr$(&H01) + Chr$(DefRSALength / 256) + Chr$(DefRSALength Mod 256) + Chr$(&H00) + Chr$(&H20) + Chr$(&H00)
    AlgAttrAut = Chr$(&H01) + Chr$(DefRSALength / 256) + Chr$(DefRSALength Mod 256) + Chr$(&H00) + Chr$(&H20) + Chr$(&H00)
    FPSig = String$(20,0)
    FPDec = String$(20,0)
    FPAut = String$(20,0)
    CAFP(1) = String$(20,0) : CAFP(2) = String$(20,0) : CAFP(3) = String$(20,0) 
    GenDateSig = String$(4,0)
    GenDateDec = String$(4,0)
    GenDateAut = String$(4,0)
    LoginData$ = ""
    URL$ = ""
    UName$ = ""
    Sex = Chr$(&H39)
    LangPref$ = "de"
    Zertifikat$ = ""
    PU1$ = ""
    PU2$ = ""
    PU3$ = ""
    PU4$ = ""
    ' Error counter for Resetting Code
    RCFBZ = 0
    ' Resetting code
    PWRC$ = ""
    ' Applikation PW (1 and 3) with default values
    EPW$(1) = "123456" : EPW$(2) = "12345678"
    ' Error counter for application PWs
    PWFBZ(1) = FBZDef : PWFBZ(2) = FBZDef
    ' LifeCycleStatus = activated
    LCS = Chr$(&H05)
End Sub

' Internal function to extract parts from Key strings
Function GetAsnInteger(Data$, Index%) as String
   Private Seq as TlvPointer
   Private Item as TlvPointer
   GetAsnInteger = ""
   Seq.Start = 1
   If 0 <> TlvReadTagLength(Seq, Data$) Then Exit Function
   Item.Info = 0
   If 0 <> TlvMatchingChild(Seq, Item, Data$, 2, Index%) Then Exit Function
   GetAsnInteger = TlvGetValue(Item, Data$)
End Function

'
'   COMMAND DEFINITIONS (APDU)
'
'   SELECT FILE:
'
'     CLA = 00
'     INS = A4
'     P1  = 04-AID
'     P2  = 00-FCI
'
Command &H00 &HA4 SelectFile(dat$)
  If P1P2 = &H0400 Then ' Select AID
    If (Lc < 1) Or (Lc > 16) Then SW1SW2 = &H6700 : Exit Command
    If dat$ = Left$(AID,len(dat$)) Then
		AppSel = 1
		If LCS <> Chr$(&H05) Then dat$ = "": SW1SW2 = &H6285 : Exit Command  ' Application termininated
		' FCP with AID and LifeCycleStatus
		dat$ = Chr$(&H62) + Chr$(21) + Chr$(&H84) + Chr$(16) + AID + Chr$(&H8A) + Chr$(1) + LCS
		If LePresent() = 0 Then dat$ = ""
		ResponseLength = Len(dat$)
		If Le = 0 Then Le = ResponseLength
		If Le > ResponseLength Then Le = ResponseLength
		If Le < ResponseLength Then dat$ = Left$(dat$, Le)
		SW1SW2 = &H9000
		Exit Command
    Else
    	SW1SW2 = &H6A82 : Exit Command
    End If
  End If
  SW1SW2 = &H6B00  ' P1/P2 error
End Command

'
'   VERIFY:
'
'     CLA = 00
'     INS = 20
'     P1  = 00 / FF
'     P2  = 81/82/83 -> Application PWx
'
Command &H00 &H20 Verify(dat$)
  ' In the early 90th the PINs of several bank card were broken with the Power Consumption/Fail attack.
  ' The programmers checked the incomming PIN with the internal content and decrement an error counter, if the PIN was wrong.
  ' Writing of the eeprom uses much more power than reading and attacked measured the power consumption of the card.
  ' If the value goes up (internal writing of eeprom) they cut the power and the error counter could not be decremented by the card.
  ' So they got another attempt to check another PIN.
  ' To solve this thje error counter must be decremented first and is resetted after the compare, so a power cut was not sufficient.
  ' But the card must be written 2 times for every PIN check. This functionality (decrementing an error counter before checking and restoring later)
  ' was patent pending and every card manufacturer has to pay for it up to the beginning of the 21th century. This is typical for several smart card routines
  ' that help to protect the card against external hardware/software attacks.
  ' Because the patent is expired, I can explain and use this mechanism in the source, but many other protections are still patent pending and under NDA.
  Private PWNr, AktPWNr
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command     ' PW not defined
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  If P1 <> 0 AND P1 <> &HFF Then SW1SW2 = &H6B00 : Exit Command    ' P1/P2 Error
  If (P2 And &HF0) <> &H80 Then SW1SW2 = &H6A88 : Exit Command    ' PW not defined
  If LePresent() <> 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  PWNr = (P2 And &H0F)
  If (PWNr < 1) Or (PWNr > 3) Then SW1SW2 = &H6A88 : Exit Command ' PW not defined
  If (PWNr = 1) Or (PWNr = 2) Then
	AktPWNr = 1
  Else 
	AktPWNr = 2
  End If
  If PWFBZ(AktPWNr) = 0 Then SW1SW2 = &H6983 : Exit Command ' PW blocked
  If Lc > 0 Then
  ' Password check
    ' decrement FBZ and reset PW-Status
    PWFBZ(AktPWNr) = PWFBZ(AktPWNr) - 1
    PWchk(PWNr) = 0
    If EPW$(AktPWNr) = dat$ Then
      ' PW OK, then set FBZ and PW-Status
      PWchk(PWNr) = 1
      PWFBZ(AktPWNr) = FBZDef
      dat$="" : SW1SW2 = &H9000
    Else
      SW1SW2 = &H6982	' PW wrong
    End If
  Else
  ' Get PW-Status or PW-Reset
    Select Case P1
      Case 00
        If PWchk(PWNr) = 1 Then
          dat$= "" : SW1SW2 = &H9000
        Else
          SW1 = &H63 : SW2 = &HC0 + PWFBZ(AktPWNr)
        End If

      Case &HFF
        PWchk(PWNr) = 0
        dat$="" : SW1SW2 = &H9000
    End Select
  End If
End Command

'
'   CHANGE REFERENCE DATA:
'
'     CLA = 00
'     INS = 24
'     P1  = 00
'     P2  = 81/83 -> Application PWx
'
Command &H00 &H24 chgrd(dat$)
  Private PWNr
  Private PWalt$, PWneu$
  If P1 <> 0 Then SW1SW2 = &H6B00 : Exit Command ' P1/P2 Error
  If (P2 And &HF0) <> &H80 Then SW1SW2 = &H6A88 : Exit Command ' PW not defined
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command ' PW not defined
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  If LePresent() <> 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  PWNr = (P2 And &H0F)
  If (PWNr <> 1) And (PWNr <> 3) Then SW1SW2 = &H6A88 : Exit Command ' PW not defined
  If PWNr = 3 Then PWNr = 2  'Reference to Admin-PW in EPW$()
  If PWFBZ(PWNr) = 0 Then SW1SW2 = &H6983  : Exit Command ' PW blocked
  PWalt$ = Left$(dat$, Len(EPW$(PWNr))) : PWneu$ = Right$(dat$, Len(dat$) - Len(EPW$(PWNr)))
  If PWNr = 2 Then
    If Len(PWneu$) < 8 Then SW1SW2 = &H6985 : Exit Command   ' New PW too short
  Else
    If Len(PWneu$) < 6 Then SW1SW2 = &H6985 : Exit Command   ' New PW too short
  End If 
  If Len(PWneu$) > MaxPWLength Then SW1SW2 = &H6985 : Exit Command   ' New PW too long
  ' Check PWalt
  ' Decrement FBZ and reset PW-Status
  PWFBZ(PWNr) = PWFBZ(PWNr) - 1
  If PWNr = 1 Then
    PWchk(1) = 0 : PWchk(2) = 0
  Else
    PWchk(3) = 0
  End If
  If PWalt$ = EPW$(PWNr) Then
    PWFBZ(PWNr) = FBZDef
    If PWNr = 1 Then
        PWchk(1) = 1
    Else
        PWchk(3) = 1
    End If
  Else
    SW1SW2 = &H6982	: Exit Command  ' PW wrong
  End If
  ' Store new password
  EPW$(PWNr) = PWneu$
  dat$="" : SW1SW2 = &H9000
End Command

'
'   RESET RETRY COUNTER:
'
'     CLA = 00
'     INS = 2C
'     P1  = 00/02 -> RC or Admin-PW
'     P2  = 81 -> Application User-PW
'
Command &H00 &H2C ResReCount(dat$)
  Private PWalt$, PWneu$
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command ' PW not defined
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  If (P1 <> 0) And (P1 <> 2) Then SW1SW2 = &H6B00 : Exit Command ' P1/P2 error
  If P2 <> &H81 Then SW1SW2 = &H6A88 : Exit Command ' PW not defined
  If LePresent() <> 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If (P1 = 2) And (PWchk(3) = 0) Then SW1SW2 = &H6982 : Exit Command  	' No PW3 check
  If (P1 = 2) And (Lc < 6) Then SW1SW2 = &H6985 : Exit Command	' PW too short
  If (P1 = 2) And (Lc > MaxPWLength) Then SW1SW2 = &H6985 : Exit Command   ' New PW too long
  If (P1 = 0) And (PWRC$ = "") Then SW1SW2 = &H6A88 : Exit Command ' RC not defined
  If P1 = 0 Then   ' RC prüfen
      If Lc < Len(PWRC$) + 6 Then SW1SW2 = &H6985 : Exit Command	' RC too short
      PWalt$ = Left$(dat$, Len(PWRC$)) : PWneu$ = Right$(dat$, Len(dat$) - Len(PWRC$))
      If Len(PWneu$) < 6 Then SW1SW2 = &H6985 : Exit Command	' PW zu kurz
      If Len(PWneu$) > MaxPWLength Then SW1SW2 = &H6985 : Exit Command   ' New PW too long
      If RCFBZ = 0 Then SW1SW2 = &H6983  : Exit Command ' RC blocked
      ' RC check
      RCFBZ = RCFBZ - 1
      If PWalt$ = PWRC$ Then
        RCFBZ = FBZDef
        dat$ = PWneu$
      Else
        SW1SW2 = &H6982	: Exit Command  ' RC wrong
      End If
  End If
  ' Store new User-PW
  EPW$(1) = dat$
  PWFBZ(1) = FBZDef
  dat$="" : SW1SW2 = &H9000
End Command

'
'   GET CHALLENGE:
'
'     CLA = 00
'     INS = 84
'     P1  = 00
'     P2  = 00
'
Command &H00 &H84 GetChallenge(dat$)
  Private proto, speed, ExtLe
  Private rlen As Integer
  If P1P2 <> 0 Then SW1SW2 = &H6B00 : Exit Command    ' P1/P2 error
  If Lc > 0 Then SW1SW2 = &H6700 : Exit Command	      ' Lc error
  If LePresent() = 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If Le > 2048 Then SW1SW2 = &H6700 : Exit Command	' Le error
  rlen = Le
  Call CommParams(proto, speed, ExtLe)
  If rlen = 0 Then
    If ExtLe = 0 Then
        rlen = 256
    Else
        rlen = 2048
    End If
  End If
  Call RandomString(dat$, rlen)
  SW1SW2 = &H9000
End Command

'
'   GENERATE ASYMMETRIC KEY PAIR:
'
'     CLA = 00
'     INS = 47
'     P1  = 80 -> Generation
'           81 -> Read actual key
'     P2  = 00
'
Command &H00 &H47 genkey(dat$)
  Private proto, speed, ExtLe
  Private i, tmpe$
  If P2 <> 0 Then SW1SW2 = &H6B00 : Exit Command ' P1/P2 Error
  If (P1 <> &H80) And (P1 <> &H81) Then SW1SW2 = &H6B00 : Exit Command ' P1/P2 Error
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  If Lc <> 2 Then SW1SW2 = &H6A80 : Exit Command ' Invalid data
  If Asc(dat$(2)) <> 0 Then SW1SW2 = &H6A80 : Exit Command ' Invalid data
  If (PWchk(3) = 0) And (P1 = &H80) Then SW1SW2 = &H6982 : Exit Command  	' No PW check
  Call CommParams(proto, speed, ExtLe)
    Select Case Asc(dat$(1))
        Case &HB6
            If (ExtLe = 0) And (ActRSALenSig > 1024) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
            If P1 = &H80 Then
                Call RsaExGenerateKey(ActRSALenSig, 0, 0, "", SigK$)
                Call RsaExPublicKey (SigK$, PubSigK$)
                Counter = String$(3,0)
				FPSig = String$(20,0)
				GenDateSig = String$(4,0)
            End If
            If SigK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
            tmpe$ = GetAsnInteger(PubSigK$, 2) : dat$ = GetAsnInteger(PubSigK$, 1)
            While Len(tmpe$) < 4
                tmpe$ = Chr$(0) + tmpe$
            Wend
            If Left$(dat$, 1) = Chr$(0) Then dat$ = Right$(dat$, Len(dat$) - 1)
            While Len(dat$) < (ActRSALenSig / 8)
                dat$ = Chr$(0) + dat$
            Wend
            dat$ = dat$ + Chr$(&H82) + Chr$(4) + tmpe$
            If ActRSALenSig = 1024 Then
                i = &H81
            Else
                i = &H82
            End If
            tmpe$ = Chr$(&H81) + Chr$(i)
            If i = &H81 Then
                tmpe$ = tmpe$ + Chr$(128)
            Else
                tmpe$ = tmpe$ + Chr$((ActRSALenSig / 8) / 256) + Chr$((ActRSALenSig / 8) Mod 256)
            End If

        Case &HB8
            If (ExtLe = 0) And (ActRSALenDec > 1024) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
            If P1 = &H80 Then
                Call RsaExGenerateKey(ActRSALenDec, 0, 0, "", DecK$)
                Call RsaExPublicKey (DecK$, PubDecK$)
				FPDec = String$(20,0)
				GenDateDec = String$(4,0)
            End If
            If DecK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
            tmpe$ = GetAsnInteger(PubDecK$, 2) : dat$ = GetAsnInteger(PubDecK$, 1)
            While Len(tmpe$) < 4
                tmpe$ = Chr$(0) + tmpe$
            Wend
            If Left$(dat$, 1) = Chr$(0) Then dat$ = Right$(dat$, Len(dat$) - 1)
            While Len(dat$) < (ActRSALenDec / 8)
                dat$ = Chr$(0) + dat$
            Wend
            dat$ = dat$ + Chr$(&H82) + Chr$(4) + tmpe$
            If ActRSALenDec = 1024 Then
                i = &H81
            Else
                i = &H82
            End If
            tmpe$ = Chr$(&H81) + Chr$(i)
            If i = &H81 Then
                tmpe$ = tmpe$ + Chr$(128)
            Else
                tmpe$ = tmpe$ + Chr$((ActRSALenDec / 8) / 256) + Chr$((ActRSALenDec / 8) Mod 256)
            End If

        Case &HA4
            If (ExtLe = 0) And (ActRSALenAut > 1024) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
            If P1 = &H80 Then
                Call RsaExGenerateKey(ActRSALenAut, 0, 0, "", AutK$)
                Call RsaExPublicKey (AutK$, PubAutK$)
				FPAut = String$(20,0)
				GenDateAut = String$(4,0)
				Zertifikat$ = ""
            End If
            If AutK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
            tmpe$ = GetAsnInteger(PubAutK$, 2) : dat$ = GetAsnInteger(PubAutK$, 1)
            While Len(tmpe$) < 4
                tmpe$ = Chr$(0) + tmpe$
            Wend
            If Left$(dat$, 1) = Chr$(0) Then dat$ = Right$(dat$, Len(dat$) - 1)
            While Len(dat$) < (ActRSALenAut / 8)
                dat$ = Chr$(0) + dat$
            Wend
            dat$ = dat$ + Chr$(&H82) + Chr$(4) + tmpe$
            If ActRSALenAut = 1024 Then
                i = &H81
            Else
                i = &H82
            End If
            tmpe$ = Chr$(&H81) + Chr$(i)
            If i = &H81 Then
                tmpe$ = tmpe$ + Chr$(128)
            Else
                tmpe$ = tmpe$ + Chr$((ActRSALenAut / 8) / 256) + Chr$((ActRSALenAut / 8) Mod 256)
            End If

        Case Else
            SW1SW2 = &H6A80 : Exit Command
    End Select

  dat$ = tmpe$ + dat$
  If i = &H81 Then
    tmpe$ = Chr$(&H7F) + Chr$(&H49) + Chr$(&H81) + Chr$(137)
  Else
    tmpe$ = Chr$(&H7F) + Chr$(&H49) + Chr$(&H82) + Chr$(Len(dat$) / 256) + Chr$(Len(dat$) Mod 256)
  End If
  dat$ = tmpe$ + dat$

  If LePresent() = 0 Then dat$ = ""
  ResponseLength = Len(dat$)
  If Le = 0 Then Le = ResponseLength
  If Le > ResponseLength Then Le = ResponseLength
  If Le < ResponseLength Then dat$ = Left$(dat$, Le)
  SW1SW2 = &H9000
End Command

'
'   PSO: COMPUTE DIGITAL SIGNATURE / DECIPHER
'
'     CLA = 00
'     INS = 2A
'     P1  = 9E / 80
'     P2  = 9A / 86
'
Command &H00 &H2A pso(dat$)
  Private TC As String*4
  Private TC1 As Long At TC
  Private x As Integer
  Private proto, speed, ExtLe
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command	' Key not found
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  Call CommParams(proto, speed, ExtLe)

  Select Case P1P2

    Case &H9E9A
      If SigK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
      If PWchk(1) = 0 Then SW1SW2 = &H6982 : Exit Command   ' No PW check
      If (ExtLe = 0) And (ActRSALenSig > 2048) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
      If Lc > ((ActRSALenSig / 8) * 0.4) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong length, more than 40% of modulus
      ' PKCS#1 formatting
      dat$ = Chr$(0) + Chr$(1) + String$((ActRSALenSig / 8) - 3 - Lc, &HFF) + Chr$(0) + dat$
      Call RsaExDecryptRaw(dat$, SigK$)
	   ' Increment Counter
      TC = Chr$(0) + Counter
	   If TC1 >= &HFFFFFF Then
        SW1SW2 = &H6F00 : Exit Command		' Counter overflow
      Else
        TC1 = TC1 + 1
      End If
      Counter = Right$(TC,3)
      If PW1once = Chr$(0) Then    ' Delete PW1 status
         PWchk(1) = 0
      End If

    Case &H8086
        If dat$(1) <> Chr$(0) And dat$(1) <> Chr$(2) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong input
        If PWchk(2) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
	    Select Case Asc(dat$(1))

			Case &H00
				' RSA Decrypt
				If DecK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key nicht definiert
				If Lc <> ((ActRSALenDec / 8) + 1) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong length
				dat$ = Right$(dat$, Len(dat$) - 1)
				Call RsaExDecryptRaw(dat$, DecK$)
				If dat$(1) <> Chr$(2) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong input
				x = 2
				While Asc(dat$(x)) <> 0
					x = x + 1
					If x > ((ActRSALenDec / 8) - 2) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong input
				Wend
				If x < 9 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong input
				dat$ = Right$(dat$, (ActRSALenDec / 8) - 1 - x)

			Case &H02
				' AESKeyDec Decrypt
				If AESKeyDec$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
				If Lc <> 17 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong length
				dat$ = Right$(dat$, Len(dat$) - 1)
				If Len(AESKeyDec$) = 16 Then
					dat$ = AES(-128, AESKeyDec$, dat$)
				Else
					dat$ = AES(-256, AESKeyDec$, dat$)
				End If
			
		End Select

    Case Else
        SW1SW2 = &H6B00 : Exit Command     ' P1/P2 error

  End Select

  If LePresent() = 0 Then dat$ = ""
  ResponseLength = Len(dat$)
  If Le = 0 Then Le = ResponseLength
  If Le > ResponseLength Then Le = ResponseLength
  If Le < ResponseLength Then dat$ = Left$(dat$, Le)
  SW1SW2 = &H9000
End Command

'
'   INTERNAL AUTHENTICATE:
'
'     CLA = 00
'     INS = 88
'     P1  = 00
'     P2  = 00
'
Command &H00 &H88 InternalAuthenticate(dat$)
  Private proto, speed, ExtLe
  If P1P2 <> 0 Then SW1SW2 = &H6B00  : Exit Command	' P1/P2 error
  If LePresent() = 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command	' Key not found
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  Call CommParams(proto, speed, ExtLe)
  If AutK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
  If (ExtLe = 0) And (ActRSALenAut > 2048) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
  If PWchk(2) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
  If Lc > ((ActRSALenAut / 8) * 0.4) Then SW1SW2 = &H6985  : Exit Command	' Wrong length

  ' PKCS#1 formatting
  dat$ = Chr$(0) + Chr$(1) + String$((ActRSALenAut / 8) - 3 - Lc, &HFF) + Chr$(0) + dat$
  Call RsaExDecryptRaw(dat$, AutK$)

  ResponseLength = Len(dat$)
  If Le = 0 Then Le = ResponseLength
  If Le > ResponseLength Then Le = ResponseLength
  If Le < ResponseLength Then dat$ = Left$(dat$, Le)
  SW1SW2 = &H9000
End Command

'
'   GET DATA:
'
'     CLA = 00
'     INS = CA
'     P1  = XX -> BER-TLV tag
'     P2  = XX -> BER-TLV tag
'
Command &H00 &HCA Getdata(dat$)
  Private proto, speed, ExtLe
  If LePresent() = 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command   ' DOs not defined
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  Call CommParams(proto, speed, ExtLe)
  If Lc > 0 Then SW1SW2 = &H6700  : Exit Command	' Wrong length
  Select Case P1P2

	Case &H006E
		dat$ = Chr$(&H4F) + Chr$(16) + AID + Chr$(&H5F) + Chr$(&H52) + Chr$(10) + Historicals + Chr$(&H73) + Chr$(&H81) + Chr$(183)_
                   + Chr$(&HC0) + Chr$(10) + ExtCap + Chr$(&HC1) + Chr$(6) + AlgAttrSig + Chr$(&HC2) + Chr$(6) + AlgAttrDec_
                   + Chr$(&HC3) + Chr$(6) + AlgAttrAut + Chr$(&HC4) + Chr$(7) + PWStatus_
                   + Chr$(PWFBZ(1)) + Chr$(RCFBZ) + Chr$(PWFBZ(2))_
                   + Chr$(&HC5) + Chr$(60) + FPSig + FPDec + FPAut_
                   + Chr$(&HC6) + Chr$(60) + CAFP(1) + CAFP(2) + CAFP(3)_
                   + Chr$(&HCD) + Chr$(12) + GenDateSig + GenDateDec + GenDateAut

	Case &H00C4
		dat$ = PWStatus + Chr$(PWFBZ(1)) + Chr$(RCFBZ) + Chr$(PWFBZ(2))

	Case &H5F50
		dat$ = URL$

	Case &H5F52
		dat$ = Historicals

	Case &H005E
		dat$ = LoginData$

	Case &H0065
		dat$ = Chr$(&H5B) + Chr$(Len(UName$)) + UName$ + Chr$(&H5F) + Chr$(&H2D) + Chr$(Len(LangPref$)) + LangPref$_
                   + Chr$(&H5F) + Chr$(&H35) + Chr$(1) + Sex

	Case &H007A
		dat$ = Chr$(&H93) + Chr$(3) + Counter

	Case &H004F
		dat$ = AID

	Case &H0101
		dat$ = PU1$

	Case &H0102
		dat$ = PU2$

	Case &H0103
        If PWchk(2) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
		dat$ = PU3$

	Case &H0104
         If PWchk(3) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
		dat$ = PU4$

	Case &H7F21
         If (ExtLe = 0) And (Len(Zertifikat$) > 256) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
         dat$ = Zertifikat$

	Case Else
		 SW1SW2 = &H6A88  : Exit Command		' DO not found

  End Select
  ResponseLength = Len(dat$)
  If Le = 0 Then Le = ResponseLength
  If Le > ResponseLength Then Le = ResponseLength
  If Le < ResponseLength Then dat$ = Left$(dat$, Le)
  SW1SW2 = &H9000
End Command

'
'   PUT DATA:
'
'     CLA = 00
'     INS = DA
'     P1  = XX -> BER-TLV tag
'     P2  = XX -> BER-TLV tag
'
Command &H00 &HDA Putdata(dat$)
  Private tmp$
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command         ' DOs not defined
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  If LePresent() <> 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If (PWchk(3) = 0) And (P1P2 <> &H0101) And (P1P2 <> &H0103) Then SW1SW2 = &H6982 : Exit Command  	' No PW check
  If Lc = 0 Then dat$ = ""
  Select Case P1P2

	Case &H005B
        If Lc > 39 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        UName$ = dat$

	Case &H005E
        If Lc > 254 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        LoginData$ = dat$

	Case &H5F2D
        If Lc > 8 Then SW1SW2 = &H6700 : Exit Command             ' Wrong length
        If Lc Mod 2 <> 0 Then SW1SW2 = &H6985 : Exit Command	' Wrong format
        LangPref$ = dat$

	Case &H5F35
        If Lc <> 1 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        Sex = dat$

	Case &H5F50
        If Lc > 254 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        URL$ = dat$

	Case &H00C1
        If Lc <> 6 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        If dat$(1) <> Chr$(1) Then SW1SW2 = &H6A80 : Exit Command	  ' Wrong value
        If Right$(dat$, 3) <> Chr$(0, &H20, 0) Then SW1SW2 = &H6A80 : Exit Command	' Wrong value
        If (Mid$(dat$, 2, 2) <> Chr$(4, 0)) And (Mid$(dat$, 2, 2) <> Chr$(8, 0)) And (Mid$(dat$, 2, 2) <> Chr$(&H0C, 0)) And (Mid$(dat$, 2, 2) <> Chr$(&H10, 0)) Then SW1SW2 = &H6A80 : Exit Command
        If (Asc(dat$(2)) * 256) + (Asc(dat$(3)) Mod 256) <> ActRSALenSig Then
                Counter = String$(3, 0)
                FPSig = String$(20,0)
                GenDateSig = String$(4,0)
                SigK$ = ""
                PubSigK$ = ""
                ActRSALenSig = (Asc(dat$(2)) * 256) + (Asc(dat$(3)) Mod 256)
        End If
        AlgAttrSig = dat$

	Case &H00C2
        If Lc <> 6 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        If dat$(1) <> Chr$(1) Then SW1SW2 = &H6A80 : Exit Command	  ' Wrong value
        If Right$(dat$, 3) <> Chr$(0, &H20, 0) Then SW1SW2 = &H6A80 : Exit Command	' Wrong value
        If (Mid$(dat$, 2, 2) <> Chr$(4, 0)) And (Mid$(dat$, 2, 2) <> Chr$(8, 0)) And (Mid$(dat$, 2, 2) <> Chr$(&H0C, 0)) And (Mid$(dat$, 2, 2) <> Chr$(&H10, 0)) Then SW1SW2 = &H6A80 : Exit Command
        If (Asc(dat$(2)) * 256) + (Asc(dat$(3)) Mod 256) <> ActRSALenDec Then
                FPDec = String$(20,0)
                GenDateDec = String$(4,0)
                DecK$ = ""
                PubDecK$ = ""
                ActRSALenDec = (Asc(dat$(2)) * 256) + (Asc(dat$(3)) Mod 256)
        End If
        AlgAttrDec = dat$

	Case &H00C3
        If Lc <> 6 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        If dat$(1) <> Chr$(1) Then SW1SW2 = &H6A80 : Exit Command	  ' Wrong value
        If Right$(dat$, 3) <> Chr$(0, &H20, 0) Then SW1SW2 = &H6A80 : Exit Command	' Wrong value
        If (Mid$(dat$, 2, 2) <> Chr$(4, 0)) And (Mid$(dat$, 2, 2) <> Chr$(8, 0)) And (Mid$(dat$, 2, 2) <> Chr$(&H0C, 0)) And (Mid$(dat$, 2, 2) <> Chr$(&H10, 0)) Then SW1SW2 = &H6A80 : Exit Command
        If (Asc(dat$(2)) * 256) + (Asc(dat$(3)) Mod 256) <> ActRSALenAut Then
                FPAut = String$(20,0)
                GenDateAut = String$(4,0)
                AutK$ = ""
                PubAutK$ = ""
                ActRSALenAut = (Asc(dat$(2)) * 256) + (Asc(dat$(3)) Mod 256)
                Zertifikat$ = ""
        End If
        AlgAttrAut = dat$

	Case &H00C4
        If Lc <> 1 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        If (dat$ <> Chr$(0)) And (dat$ <> Chr$(1)) Then SW1SW2 = &H6A88 : Exit Command    ' DO not defined
        PW1once = dat$

	Case &H00C7
        If Lc <> 20 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        FPSig = dat$

	Case &H00C8
        If Lc <> 20 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        FPDec = dat$

	Case &H00C9
        If Lc <> 20 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        FPAut = dat$

	Case &H00CA
        If Lc <> 20 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        CAFP(1) = dat$

	Case &H00CB
        If Lc <> 20 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        CAFP(2) = dat$

	Case &H00CC
        If Lc <> 20 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        CAFP(3) = dat$

      Case &H00CE
        If Lc <> 4 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        GenDateSig = dat$

      Case &H00CF
        If Lc <> 4 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        GenDateDec = dat$

      Case &H00D0
        If Lc <> 4 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        GenDateAut = dat$

      Case &H00D3
        If Lc = 0 Then          ' Special case: delete RC
            PWRC$ = "" : RCFBZ = 0
        Else
            If Lc < 8 Then SW1SW2 = &H6985 : Exit Command       ' RC too short
            If Lc > MaxPWLength Then SW1SW2 = &H6985 : Exit Command       ' RC too long
            PWRC$ = dat$ : RCFBZ = FBZDef
        End If

      Case &H00D5
            If Lc <> 16 And Lc <> 32 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
            AESKeyDec$ = dat$

      Case &H7F21
            If Lc > 2048 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
            Zertifikat$ = dat$

	Case &H0101
        If PWchk(2) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
        If Lc > 254 Then SW1SW2 = &H6700 : Exit Command	      ' Wrong length
        PU1$ = dat$

	Case &H0102
        If Lc > 254 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        PU2$ = dat$

	Case &H0103
        If PWchk(2) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
        If Lc > 254 Then SW1SW2 = &H6700 : Exit Command	      ' Wrong length
        PU3$ = dat$

	Case &H0104
        If Lc > 254 Then SW1SW2 = &H6700 : Exit Command	' Wrong length
        PU4$ = dat$

	Case Else
		SW1SW2 = &H6A88  : Exit Command		' DO not defined

  End Select
  dat$ = "" : SW1SW2 = &H9000
End Command

'
'   PUT DATA:       ODD INS for Key-Import
'
'     CLA = 00
'     INS = DB
'     P1  = 3F
'     P2  = FF
'
Command &H00 &HDB PutdataOdd(dat$)
  Private Keyref, p$, e$
  Private Check1024 As String*13 = &H7F,&H48,&H06,&H91,&H04,&H92,&H40,&H93,&H40,&H5F,&H48,&H81,&H84
  Private Check2048 As String*16 = &H7F,&H48,&H08,&H91,&H04,&H92,&H81,&H80,&H93,&H81,&H80,&H5F,&H48,&H82,&H01,&H04
  Private Check3072 As String*16 = &H7F,&H48,&H08,&H91,&H04,&H92,&H81,&HC0,&H93,&H81,&HC0,&H5F,&H48,&H82,&H01,&H84
  Private Check4096 As String*18 = &H7F,&H48,&H0A,&H91,&H04,&H92,&H82,&H01,&H00,&H93,&H82,&H01,&H00,&H5F,&H48,&H82,&H02,&H04
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command         ' DOs not defined
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  If LePresent() <> 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If P1P2 <> &H3FFF Then SW1SW2 = &H6B00  : Exit Command	' P1/P2 Error
  If PWchk(3) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
  If Left$(dat$, 2) <> Chr$(&H4D, &H81) And Left$(dat$, 2) <> Chr$(&H4D, &H82) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
  If Mid$(dat$, 2, 1) = Chr$(&H82) Then
      If Mid$(dat$, 3, 2) <> Chr$((Lc - 4) / 256) + Chr$((Lc - 4) mod 256) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
      dat$ = Right$(dat$, Lc - 4)
  Else
      If Mid$(dat$, 3, 1) <> Chr$(Lc - 3) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
      dat$ = Right$(dat$, Lc - 3)
  End If
  If (dat$(1) <> Chr$(&HB6)) And (dat$(1) <> Chr$(&HB8)) And (dat$(1) <> Chr$(&HA4)) Then SW1SW2 = &H6A88 : Exit Command	' Wrong parameter in data
  Keyref = Asc(dat$(1))     ' Store referenced Key
  If dat$(2) <> Chr$(0) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
  dat$ = Right$(dat$, Len(dat$) - 2)

  Select Case Keyref

	Case &HB6
        If (ActRSALenSig = 1024) And (Left$(dat$, 13) <> Check1024) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If (ActRSALenSig = 2048) And (Left$(dat$, 16) <> Check2048) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If (ActRSALenSig = 3072) And (Left$(dat$, 16) <> Check3072) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If (ActRSALenSig = 4096) And (Left$(dat$, 18) <> Check4096) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If ActRSALenSig = 1024 Then dat$ = Right$(dat$, 132) : If Len(dat$) <> 132 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If ActRSALenSig = 2048 Then dat$ = Right$(dat$, 260) : If Len(dat$) <> 260 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If ActRSALenSig = 3072 Then dat$ = Right$(dat$, 388) : If Len(dat$) <> 388 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If ActRSALenSig = 4096 Then dat$ = Right$(dat$, 516) : If Len(dat$) <> 516 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        ' e backup
        e$ = Left$(dat$, 4) : dat$ = Right$(dat$, Len(dat$) - 4)
        ' p backup
        p$ = Left$(dat$, ActRSALenSig / 16)
        ' Rest of dat$ is q
        dat$ = Right$(dat$, ActRSALenSig / 16)
        ' Calculate new CRT-Key from p, q and e
        Call RsaExConstructKey (p$, dat$, e$, SigK$)
        ' Generate PubKey, delete relevant DOs with old data
        Call RsaExPublicKey (SigK$, PubSigK$)
        Counter = String$(3,0)
        FPSig = String$(20,0)
        GenDateSig = String$(4,0)

	Case &HB8
        If (ActRSALenDec = 1024) And (Left$(dat$, 13) <> Check1024) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If (ActRSALenDec = 2048) And (Left$(dat$, 16) <> Check2048) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If (ActRSALenDec = 3072) And (Left$(dat$, 16) <> Check3072) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If (ActRSALenDec = 4096) And (Left$(dat$, 18) <> Check4096) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If ActRSALenDec = 1024 Then dat$ = Right$(dat$, 132) : If Len(dat$) <> 132 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If ActRSALenDec = 2048 Then dat$ = Right$(dat$, 260) : If Len(dat$) <> 260 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If ActRSALenDec = 3072 Then dat$ = Right$(dat$, 388) : If Len(dat$) <> 388 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If ActRSALenDec = 4096 Then dat$ = Right$(dat$, 516) : If Len(dat$) <> 516 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        ' e backup
        e$ = Left$(dat$, 4) : dat$ = Right$(dat$, Len(dat$) - 4)
        ' p backup
        p$ = Left$(dat$, ActRSALenDec / 16)
        ' Rest of dat$ is q
        dat$ = Right$(dat$, ActRSALenDec / 16)
        ' Calculate new CRT-Key from p, q and e
        Call RsaExConstructKey (p$, dat$, e$, DecK$)
        ' Generate PubKey, delete relevant DOs with old data
        Call RsaExPublicKey (DecK$, PubDecK$)
        FPDec = String$(20,0)
        GenDateDec = String$(4,0)

	Case &HA4
        If (ActRSALenAut = 1024) And (Left$(dat$, 13) <> Check1024) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If (ActRSALenAut = 2048) And (Left$(dat$, 16) <> Check2048) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If (ActRSALenAut = 3072) And (Left$(dat$, 16) <> Check3072) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If (ActRSALenAut = 4096) And (Left$(dat$, 18) <> Check4096) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If ActRSALenAut = 1024 Then dat$ = Right$(dat$, 132) : If Len(dat$) <> 132 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If ActRSALenAut = 2048 Then dat$ = Right$(dat$, 260) : If Len(dat$) <> 260 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If ActRSALenAut = 3072 Then dat$ = Right$(dat$, 388) : If Len(dat$) <> 388 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        If ActRSALenAut = 4096 Then dat$ = Right$(dat$, 516) : If Len(dat$) <> 516 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
        ' e backup
        e$ = Left$(dat$, 4) : dat$ = Right$(dat$, Len(dat$) - 4)
        ' p backup
        p$ = Left$(dat$, ActRSALenAut / 16)
        ' Rest von dat$ ist q
        dat$ = Right$(dat$, ActRSALenAut / 16)
        ' Calculate new CRT-Key from p, q and e
        Call RsaExConstructKey (p$, dat$, e$, AutK$)
        ' Generate PubKey, delete relevant DOs with old data
        Call RsaExPublicKey (AutK$, PubAutK$)
        FPAut = String$(20,0)
        GenDateAut = String$(4,0)
        Zertifikat$ = ""

	Case Else
		SW1SW2 = &H6A88  : Exit Command		' DO not defined

  End Select
  dat$ = "" : SW1SW2 = &H9000
End Command

'
'   TERMINATE DF:
'
'     CLA = 00
'     INS = E6
'     P1  = 00
'     P2  = 00
'
Command &H00 &HE6 TermDF(dat$)
  Private AdmPWdef
  AdmPWdef = 0
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command   ' App not selected
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  If P1P2 <> 0 Then SW1SW2 = &H6B00 : Exit Command    ' P1/P2 Error
  If Lc > 0 Then SW1SW2 = &H6700 : Exit Command	      ' Lc Error
  If LePresent() <> 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  ' Check for unusable Admin-PW
  If PWFBZ(2) = 0 Then AdmPWdef = 1
  If PWchk(3) = 0 And AdmPWdef = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
  LCS = Chr$(&H03)    ' Set LifeCycleStatus to Initialisation state
  dat$ = "" : SW1SW2 = &H9000
End Command

'
'   ACTIVATE FILE:
'
'     CLA = 00
'     INS = 44
'     P1  = 00
'     P2  = 00
'
Command &H00 &H44 ActFile(dat$)
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command   ' App not selected
  If P1P2 <> 0 Then SW1SW2 = &H6B00 : Exit Command    ' P1/P2 Error
  If Lc > 0 Then SW1SW2 = &H6700 : Exit Command	      ' Lc Error
  If LePresent() <> 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If LCS = Chr$(&H03) Then Call CardInit
  dat$ = "" : SW1SW2 = &H9000
End Command


Command Else unknown(dat$)
  If CLA <> 0 Then
	SW1SW2 = &H6E00	'Unknown CLA
    If (CLA And &H10) = &H10 Then SW1SW2 = &H6884         'Chaining not supported
    If (CLA And &H03) > 0 Then SW1SW2 = &H6881            'Logical channels not supported
    If (CLA And &H0C) > 0 Then SW1SW2 = &H6882            'SM not supported
  Else
	SW1SW2 = &H6D00	'Unknown INS
  End If
End Command

