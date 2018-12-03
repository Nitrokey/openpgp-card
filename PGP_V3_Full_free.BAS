Rem BasicCard (7.5_D) Source Code for OpenPGP Card
Rem Version 3.3 Free
Rem Copyright (C)2018 Achim Pietig (openpgp@pietig.com)
Rem All commands, functions and DOs from the V3.3.2 specification, except Secure Messaging

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
' This source code has the same functionality as the sold version, but has no internal security hardenings. All lines with these additional checks (RAM and EEPROM) are removed, the remaining code is identical.
' Smart card programming differs from normal source code for e. g. PCs, because there are several hardware attacks against the content of a smart card (e. g. Power fail attack, DPA, DFA).
' The knowledge/code to protect a card against these attacks was given to me under NDA.
'
' The pre-defined AID in the source generates test cards with a constant serial number. If a user needs different serials, the AID in the source should be aligned.
' Users/vendors without manufacturer registration from FSFE/Gnupg e. V. shall not change the manufacturer ID in the source and are only allowed to produce test cards (manufacturer ID = 0000 or FFFF).
' Registered manufactures should have special functions on their production machines to provide unique serial numbers to OpenPGP smart cards.
'
' Differences with the "commercial" card (produced by Zeitcontrol):
' NDA-related checks of RAM and EEPROM are removed
' Disabling of several Zeitcontrol-Basiccard routines is removed
' Proprietary personalisation routine for Zeitcontrol is removed
' To fit on the Basiccard 7.5 the size of some DOs is reduced to 255 bytes (see Extended Capabilities)
' On a BC 7.5 and setting the card to RSA 4096, it may be possible that the EEPROM is too small for storing all DOs (e. g. all certificates) with the maximum length. 

DefByte A-Z
Option Explicit
Option Base 1
#Files 0    'Kein file system
#Include RSA.DEF
#Include Crypto.def
#Include MISC.DEF
#Include Tlv12.def
#Include EC-p.def

' Unused algorithms are switched off
Disable Encryption &H21,&H22,&H23,&H24,&H25,&H32,&H41,&H42,&H43,&H81,&H82,&H83

' Reset of the whole application with TERMINATE and ACTIVATE
Declare Sub CardInit()

' Internal function to extract key parts from Key-Strings
Declare Function GetAsnInteger(Data$, Index%) as String

' Read content of an object specified with it's Tag in SearchTag from a given string (Tdata).
' Occurrence can be set for multiple objects with the same Tag in TOccurrence, any value <= 1 returns the first found object.
' The maximum count of any occurrence of the object is returned in TOcurrence.
' If no object with the given Tag was found, 0 is retrurned in TOccurrence.
' The behaviour is similar to a Get Data (7816-4) command.
Declare Function TlvGetData(ByVal SearchTag As String, ByVal Tdata As String, ByRef TOccurrence As Integer) As String

'
' ATR - Definition (T=1, 115200 Baud, 10 Historicals)
' Historicals = Card service data + Card capatibilities + Status
#Pragma ATR(T=1, FI=1, DI=8, HB=Chr$(0)+Chr$(&H31)+Chr$(&HF5)+Chr$(&H73)+Chr$(&HC0)+Chr$(&H01)+Chr$(&H60)+Chr$(0)+Chr$(&H90)+Chr$(0))

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
Const MaxPWLength = 64
' Modus for AES_ENC-DEC (CBC, no ICV, no Padding)
Const AES128Mode = &HB121
Const AES256Mode = &HB123
' Curve IDs
Const P256 = 17
Const P384 = 18
Const P521 = 19
Const BP256 = 7
Const BP384 = 11
Const BP512 = 13

' EEPROM:
' AID for testcard and ser-no 1
Eeprom AID As String*16 = &HD2,&H76,&H00,&H01,&H24,&H01,&H03,&H03,&H00,&H00,&H00,&H00,&H00,&H01,&H00,&H00
' Sequence counter for signatures
Eeprom Counter As String*3 = String$(3, 0)
' Application-PW (1 and 3) with default values
Eeprom EPW$(2) = "123456", "12345678"
' Error counter for application-PWs
Eeprom PWFBZ(2) = FBZDef, FBZDef
' Resetting code
Eeprom PWRC$ = ""
' Error counter for Resetting Code
Eeprom RCFBZ = 0

' Actual Alg-Length/IDs
Eeprom ActRSALenSig As Integer = DefRSALength
Eeprom ActRSALenDec As Integer = DefRSALength
Eeprom ActRSALenAut As Integer = DefRSALength
Eeprom ActELCcidSig = 0
Eeprom ActELCcidDec = 0
Eeprom ActELCcidAut = 0
Eeprom ActELCLenSig = 0
Eeprom ActELCLenDec = 0
Eeprom ActELCLenAut = 0

' Fixed DOs
Eeprom ExtCap As String*10 = &H7F,&H00,&H08,&H00,&H08,&H00,&H00,&HFF,&H00,&H01
Eeprom PWStatus As String*4 = &H00,MaxPWLength,MaxPWLength,MaxPWLength  'Whithout FBZ
Eeprom Historicals As String*10 = &H00,&H31,&HF5,&H73,&HC0,&H01,&H60,&H05,&H90,&H00 ' Application with LCS
Eeprom ExtLenInf As String*8 = &H02,&H02,&H08,&H00,&H02,&H02,&H08,&H00

' Changeable DOs (PUT DATA)
Eeprom LCS As String*1 At Historicals + 7
Eeprom PW1once As String*1 At PWStatus
Eeprom AlgAttrSig As String = Chr$(&H01) + Chr$(DefRSALength / 256) + Chr$(DefRSALength Mod 256) + Chr$(&H00) + Chr$(&H20) + Chr$(&H00)
Eeprom AlgAttrDec As String = Chr$(&H01) + Chr$(DefRSALength / 256) + Chr$(DefRSALength Mod 256) + Chr$(&H00) + Chr$(&H20) + Chr$(&H00)
Eeprom AlgAttrAut As String = Chr$(&H01) + Chr$(DefRSALength / 256) + Chr$(DefRSALength Mod 256) + Chr$(&H00) + Chr$(&H20) + Chr$(&H00)
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
Eeprom AESKeyPSO$ = ""
Eeprom SigK$ = ""
Eeprom DecK$ = ""
Eeprom AutK$ = ""
Eeprom Zertifikat(3) As String = "","",""
Eeprom PU1$ = ""
Eeprom PU2$ = ""
Eeprom PU3$ = ""
Eeprom PU4$ = ""
Eeprom KDF$ = Chr$(&H81) + Chr$(&H01) + Chr$(&H00)

' RAM:
' Flag for application selection
Public AppSel = 0
' Flags for PW checks (1-3)
Public PWchk(3) = 0,0,0
' Zert-Number
Public ZertNr = 1
' Key number for MSE command
Public KeyNrDec = 2
Public KeyNrAut = 3

' New initialisation
Sub CardInit()
    ' Sequence counter for signatures
    Counter = String$(3, 0)
    ' Keys
    AESKeyPSO$ = ""
    SigK$ = ""
    DecK$ = ""
    AutK$ = ""
    ' Actual Algo-Length/IDs
    ActRSALenSig = DefRSALength
    ActRSALenDec = DefRSALength
    ActRSALenAut = DefRSALength
	 ActELCcidSig = 0
	 ActELCcidDec = 0
	 ActELCcidAut = 0
    ActELCLenSig = 0
    ActELCLenDec = 0
    ActELCLenAut = 0

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
    Zertifikat(1) = "" : Zertifikat(2) = "" : Zertifikat(3) = ""
    PU1$ = ""
    PU2$ = ""
    PU3$ = ""
    PU4$ = ""
    KDF$ = Chr$(&H81) + Chr$(&H01) + Chr$(&H00)

    ' Error counter for Resetting Code
    RCFBZ = 0
    ' Resetting code
    PWRC$ = ""
    ' Application-PWs (1 and 3) with default values
    EPW$(1) = "123456" : EPW$(2) = "12345678"
    ' Error counter for application PWs
    PWFBZ(1) = FBZDef : PWFBZ(2) = FBZDef
    ' LifeCicleStatus activated
    LCS = Chr$(&H05)
End Sub

' Internal function to extract key parts from Key-Strings
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

' Read content of an object specified with it's Tag in SearchTag from a given string (Tdata).
Function TlvGetData(ByVal SearchTag As String, ByVal Tdata As String, ByRef TOccurrence As Integer) As String
  Private DOnr As Integer
  Private actTlv As TlvPointer
  actTlv.Start = 1
  Private ST As Integer
  Private STconv As String*2 At ST
    If TOccurrence < 2 Then
      DOnr = 1
  Else
      DOnr = TOccurrence
  End If
  TOccurrence = 0
  TlvGetData = ""
  If Len(SearchTag) > 2 Or Len(SearchTag) = 0 Then Exit Function
  If Len(SearchTag) = 1 Then SearchTag = Chr$(0) + SearchTag
  STconv = SearchTag    ' Converts Tag As String to Short, Result in ST
  While Len(Tdata) - actTlv.Start > 1
      If TlvReadTagLength(actTlv, TData) <> TlvENoError Then Exit Function
      If actTlv.Tag = ST Then
          TOccurrence = TOccurrence + 1
          If TOccurrence = DOnr Then TlvGetData = TlvGetValue(actTlv, TData)
      End If
      actTlv.Start = actTlv.Start + (actTlv.Info And &H0F)
      If (actTlv.Info And &H20) = 0 Then actTlv.Start = actTlv.Start + actTlv.Length
  Wend
End Function


'   Commands
'
'   SELECT:
'
'     CLA = 00
'     INS = A4
'     P1  = 04-AID
'     P2  = 00-FCI
'
Command &H00 &HA4 SelectFile(dat$)
  Private FreeMem As ProFreeMemoryData
  Private TC As String*4
  Private TC1 As Long At TC
  If P1P2 = &H0400 Then ' Select AID
    If (Lc < 1) Or (Lc > 16) Then SW1SW2 = &H6700 : Exit Command
    If dat$ = Left$(AID,len(dat$)) Then
       AppSel = 1
       If LCS <> Chr$(&H05) Then dat$ = "": SW1SW2 = &H6285 : Exit Command  ' App terminated
       ZertNr = 1
       KeyNrDec = 2 : KeyNrAut = 3
	   Call GetFreeMemory(FreeMem) : TC1 = FreeMem.TotalFreeEeprom
       ' FCI mit FCP (AID und LifeCycleStatus) und FMD (FreeEprom)
	   dat$ = Chr$(&H6F) + Chr$(29) + Chr$(&H62) + Chr$(21) + Chr$(&H84) + Chr$(16) + AID + Chr$(&H8A) + Chr$(1) + LCS + Chr$(&H64) + Chr$(4) + Chr$(&H53) + Chr$(2) + Right$(TC, 2)
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

'   SELECT DATA:
'
'     CLA = 00
'     INS = A5
'     P1  = 00-02 Occurrences to skip
'     P2  = 04 Select first occurrence after skipping
'
Command &H00 &HA5 SelectData(dat$)
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command     ' Application not selected
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  If Lc <> 6 Then SW1SW2 = &H6700 : Exit Command
  If P2 <> 4 Then SW1SW2 = &H6B00 : Exit Command    ' P1/P2 Error
  If P1 > 2 Then SW1SW2 = &H6B00 : Exit Command     ' P1/P2 Error
  If Left$(dat$, 4) <> Chr$(&H60) + Chr$(4) + Chr$(&H5C) + Chr$(2) Then SW1SW2 = &H6A80 : Exit Command		' Incorrect parameters in data field
  If Right$(dat$, 2) <> Chr$(&H7F) + Chr$(&H21) Then SW1SW2 = &H6A88 : Exit Command		' DO not found
  ZertNr = P1 + 1
  dat$ = ""
  SW1SW2 = &H9000
End Command

'
'   VERIFY:
'
'     CLA = 00/0C
'     INS = 20
'     P1  = 00 / FF
'     P2  = 81/82/83 -> Application PWx
'
Command &H00 &H20 Verify(dat$)
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
  ' Passwort-Prüfung
    ' Decrement and reset PW status
    PWFBZ(AktPWNr) = PWFBZ(AktPWNr) - 1
    PWchk(PWNr) = 0
    If EPW$(AktPWNr) = dat$ Then
      ' PW OK, then set FBZ and PW status
      PWchk(PWNr) = 1
      PWFBZ(AktPWNr) = FBZDef
      dat$="" : SW1SW2 = &H9000
    Else
      SW1SW2 = &H6982	' PW wrong
    End If
  Else
  ' PW status or PW reset
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
'     CLA = 00/0C
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
  If PWNr = 3 Then PWNr = 2  'Reference to admin-PW in EPW$()
  If PWFBZ(PWNr) = 0 Then SW1SW2 = &H6983  : Exit Command ' PW blocked
  PWalt$ = Left$(dat$, Len(EPW$(PWNr))) : PWneu$ = Right$(dat$, Len(dat$) - Len(EPW$(PWNr)))
  If PWNr = 2 Then
    If Len(PWneu$) < 8 Then SW1SW2 = &H6985 : Exit Command   ' New PW too short
  Else
    If Len(PWneu$) < 6 Then SW1SW2 = &H6985 : Exit Command   ' New PW too short
  End If 
  If Len(PWneu$) > MaxPWLength Then SW1SW2 = &H6985 : Exit Command   ' New PW too long
  ' First check PWalt
  ' Decrement FBZ and reset PW status
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
  ' Store new PW
  EPW$(PWNr) = PWneu$
  dat$="" : SW1SW2 = &H9000
End Command

'
'   RESET RETRY COUNTER:
'
'     CLA = 00/0C
'     INS = 2C
'     P1  = 00/02 -> RC or Admin-PW/SM
'     P2  = 81 -> Application User-PW
'
Command &H00 &H2C ResReCount(dat$)
  Private PWalt$, PWneu$
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command ' PW not defined
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  If (P1 <> 0) And (P1 <> 2) Then SW1SW2 = &H6B00 : Exit Command ' P1/P2 Error
  If P2 <> &H81 Then SW1SW2 = &H6A88 : Exit Command ' PW not defined
  If LePresent() <> 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If (P1 = 2) And (PWchk(3) = 0) Then SW1SW2 = &H6982 : Exit Command  	' No PW3 check
  If (P1 = 2) And (Lc < 6) Then SW1SW2 = &H6985 : Exit Command	' PW too short
  If (P1 = 2) And (Lc > MaxPWLength) Then SW1SW2 = &H6985 : Exit Command   ' New PW too long
  If (P1 = 0) And (PWRC$ = "") Then SW1SW2 = &H6A88 : Exit Command ' RC not defined
  If P1 = 0 Then   ' Check RC
      If Lc < Len(PWRC$) + 6 Then SW1SW2 = &H6985 : Exit Command	' RC too short
      PWalt$ = Left$(dat$, Len(PWRC$)) : PWneu$ = Right$(dat$, Len(dat$) - Len(PWRC$))
      If Len(PWneu$) < 6 Then SW1SW2 = &H6985 : Exit Command	' PW too short
      If Len(PWneu$) > MaxPWLength Then SW1SW2 = &H6985 : Exit Command   ' Neues PW too long
      If RCFBZ = 0 Then SW1SW2 = &H6983  : Exit Command ' RC blocked
      ' Checking RC
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
  If P1P2 <> 0 Then SW1SW2 = &H6B00 : Exit Command    ' P1/P2 Error
  If Lc > 0 Then SW1SW2 = &H6700 : Exit Command	      ' Lc Error
  If LePresent() = 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If Le > 2048 Then SW1SW2 = &H6700 : Exit Command	' Le Error
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
'     CLA = 00/0C
'     INS = 47
'     P1  = 80 -> Generation
'           81 -> Read actual key
'     P2  = 00
'
Command &H00 &H47 genkey(dat$)
  Private proto, speed, ExtLe
  Private tmpe$, PKey$
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  If P2 <> 0 Then SW1SW2 = &H6B00 : Exit Command ' P1/P2 Error
  If (P1 <> &H80) And (P1 <> &H81) Then SW1SW2 = &H6B00 : Exit Command ' P1/P2 Error
  If Lc <> 2 Then SW1SW2 = &H6A80 : Exit Command ' Invalid data
  If Asc(dat$(2)) <> 0 Then SW1SW2 = &H6A80 : Exit Command ' Invalid data
  If (PWchk(3) = 0) And (P1 = &H80) Then SW1SW2 = &H6982 : Exit Command  	' No PW check
  Call CommParams(proto, speed, ExtLe)
  PKey$ = ""
    Select Case Asc(dat$(1))
        Case &HB6
            If ActRSALenSig > 1024 Then
                If ExtLe = 0 Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
                If P1 = &H80 Then
                    Call RsaExGenerateKey(ActRSALenSig, 0, 0, "", SigK$)
                    Counter = String$(3,0)
                    Zertifikat(3) = ""
                    FPSig = String$(20,0)
                    GenDateSig = String$(4,0)
                End If
                If SigK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
                Call RsaExPublicKey (SigK$, PKey$)
                tmpe$ = GetAsnInteger(PKey$, 2) : dat$ = GetAsnInteger(PKey$, 1)
                While Len(tmpe$) < 4
                    tmpe$ = Chr$(0) + tmpe$
                Wend
                If Left$(dat$, 1) = Chr$(0) Then dat$ = Right$(dat$, Len(dat$) - 1)
                While Len(dat$) < (ActRSALenSig / 8)
                    dat$ = Chr$(0) + dat$
                Wend
                dat$ = dat$ + Chr$(&H82) + Chr$(4) + tmpe$
                tmpe$ = Chr$(&H81) + Chr$(&H82)
                tmpe$ = tmpe$ + Chr$((ActRSALenSig / 8) / 256) + Chr$((ActRSALenSig / 8) Mod 256)
                dat$ = tmpe$ + dat$
                tmpe$ = Chr$(&H7F) + Chr$(&H49) + Chr$(&H82) + Chr$(Len(dat$) / 256) + Chr$(Len(dat$) Mod 256)
                dat$ = tmpe$ + dat$
            Else
                Call ECpSetCurve(ActELCcidSig)
                If P1 = &H80 Then
                    Call ECpGenerateKeyPair(SigK$, PKey$)
                    Counter = String$(3,0)
                    Zertifikat(3) = ""
                    FPSig = String$(20,0)
                    GenDateSig = String$(4,0)
                End If
                If SigK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
                If PKey$ = "" Then Call ECpMakePublicKey(SigK$, PKey$)
                PKey$ = Chr$(&H04) + PKey$
                If Len(PKey$) > 127 Then
                    dat$ = Chr$(&H86) + Chr$(&H81) + Chr$(Len(PKey$)) + PKey$
                Else
                    dat$ = Chr$(&H86) + Chr$(Len(PKey$)) + PKey$
                End If
                If Len(dat$) > 127 Then
                    tmpe$ = Chr$(&H7F) + Chr$(&H49) + Chr$(&H81) + Chr$(Len(dat$))
                Else
                    tmpe$ = Chr$(&H7F) + Chr$(&H49) + Chr$(Len(dat$))
                End If
                dat$ = tmpe$ + dat$
            End If
            
        Case &HB8
            If ActRSALenDec > 1024 Then
                If ExtLe = 0 Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
                If P1 = &H80 Then
                    Call RsaExGenerateKey(ActRSALenDec, 0, 0, "", DecK$)
                    Zertifikat(2) = ""
                    FPDec = String$(20,0)
                    GenDateDec = String$(4,0)
                End If
                If DecK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
                Call RsaExPublicKey (DecK$, PKey$)
                tmpe$ = GetAsnInteger(PKey$, 2) : dat$ = GetAsnInteger(PKey$, 1)
                While Len(tmpe$) < 4
                    tmpe$ = Chr$(0) + tmpe$
                Wend
                If Left$(dat$, 1) = Chr$(0) Then dat$ = Right$(dat$, Len(dat$) - 1)
                While Len(dat$) < (ActRSALenDec / 8)
                    dat$ = Chr$(0) + dat$
                Wend
                dat$ = dat$ + Chr$(&H82) + Chr$(4) + tmpe$
                tmpe$ = Chr$(&H81) + Chr$(&H82)
                tmpe$ = tmpe$ + Chr$((ActRSALenDec / 8) / 256) + Chr$((ActRSALenDec / 8) Mod 256)
                dat$ = tmpe$ + dat$
                tmpe$ = Chr$(&H7F) + Chr$(&H49) + Chr$(&H82) + Chr$(Len(dat$) / 256) + Chr$(Len(dat$) Mod 256)
                dat$ = tmpe$ + dat$
            Else
                Call ECpSetCurve(ActELCcidDec)
                If P1 = &H80 Then
                    Call ECpGenerateKeyPair(DecK$, PKey$)
                    Zertifikat(2) = ""
                    FPDec = String$(20,0)
                    GenDateDec = String$(4,0)
                End If
                If DecK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
                If PKey$ = "" Then Call ECpMakePublicKey(DecK$, PKey$)
                PKey$ = Chr$(&H04) + PKey$
                If Len(PKey$) > 127 Then
                    dat$ = Chr$(&H86) + Chr$(&H81) + Chr$(Len(PKey$)) + PKey$
                Else
                    dat$ = Chr$(&H86) + Chr$(Len(PKey$)) + PKey$
                End If
                If Len(dat$) > 127 Then
                    tmpe$ = Chr$(&H7F) + Chr$(&H49) + Chr$(&H81) + Chr$(Len(dat$))
                Else
                    tmpe$ = Chr$(&H7F) + Chr$(&H49) + Chr$(Len(dat$))
                End If
                dat$ = tmpe$ + dat$
            End If

        Case &HA4
            If ActRSALenAut > 1024 Then
                If ExtLe = 0 Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
                If P1 = &H80 Then
                    Call RsaExGenerateKey(ActRSALenAut, 0, 0, "", AutK$)
                    Zertifikat(1) = ""
                    FPAut = String$(20,0)
                    GenDateAut = String$(4,0)
                End If
                If AutK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
                Call RsaExPublicKey (AutK$, PKey$)
                tmpe$ = GetAsnInteger(PKey$, 2) : dat$ = GetAsnInteger(PKey$, 1)
                While Len(tmpe$) < 4
                    tmpe$ = Chr$(0) + tmpe$
                Wend
                If Left$(dat$, 1) = Chr$(0) Then dat$ = Right$(dat$, Len(dat$) - 1)
                While Len(dat$) < (ActRSALenAut / 8)
                    dat$ = Chr$(0) + dat$
                Wend
                dat$ = dat$ + Chr$(&H82) + Chr$(4) + tmpe$
                tmpe$ = Chr$(&H81) + Chr$(&H82)
                tmpe$ = tmpe$ + Chr$((ActRSALenAut / 8) / 256) + Chr$((ActRSALenAut / 8) Mod 256)
                dat$ = tmpe$ + dat$
                tmpe$ = Chr$(&H7F) + Chr$(&H49) + Chr$(&H82) + Chr$(Len(dat$) / 256) + Chr$(Len(dat$) Mod 256)
                dat$ = tmpe$ + dat$
            Else
                Call ECpSetCurve(ActELCcidAut)
                If P1 = &H80 Then
                    Call ECpGenerateKeyPair(AutK$, PKey$)
                    Zertifikat(1) = ""
                    FPAut = String$(20,0)
                    GenDateAut = String$(4,0)
                End If
                If AutK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
                If PKey$ = "" Then Call ECpMakePublicKey(AutK$, PKey$)
                PKey$ = Chr$(&H04) + PKey$
                If Len(PKey$) > 127 Then
                    dat$ = Chr$(&H86) + Chr$(&H81) + Chr$(Len(PKey$)) + PKey$
                Else
                    dat$ = Chr$(&H86) + Chr$(Len(PKey$)) + PKey$
                End If
                If Len(dat$) > 127 Then
                    tmpe$ = Chr$(&H7F) + Chr$(&H49) + Chr$(&H81) + Chr$(Len(dat$))
                Else
                    tmpe$ = Chr$(&H7F) + Chr$(&H49) + Chr$(Len(dat$))
                End If
                dat$ = tmpe$ + dat$
            End If

        Case Else
            SW1SW2 = &H6A80 : Exit Command
    End Select

  If LePresent() = 0 Then dat$ = ""
  ResponseLength = Len(dat$)
  If Le = 0 Then Le = ResponseLength
  If Le > ResponseLength Then Le = ResponseLength
  If Le < ResponseLength Then dat$ = Left$(dat$, Le)
  SW1SW2 = &H9000
End Command

'
'   PSO: COMPUTE DIGITAL SIGNATURE / DECIPHER /ENCIPHER
'
'     CLA = 00
'     INS = 2A
'     P1  = 9E / 80 / 86
'     P2  = 9A / 86 / 80
'
Command &H00 &H2A pso(dat$)
  Private tmp$
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
      If ActRSALenSig > 1024 Then
          If (ExtLe = 0) And (ActRSALenSig > 2048) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
          If Lc > ((ActRSALenSig / 8) * 0.4) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong length, more than 40% of Modulus
          ' PKCS#1 formatting
          dat$ = Chr$(0) + Chr$(1) + String$((ActRSALenSig / 8) - 3 - Lc, &HFF) + Chr$(0) + dat$
          Call RsaExDecryptRaw(dat$, SigK$)
      Else
          ' Check for valid hash input and fill up if needed
          If ActELCLenSig = 32 Then
            If Len(dat$) > 32 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
            While Len(dat$) < 32
                dat$ = Chr$(0) + dat$
            Wend
          End If
          If ActELCLenSig = 48 Then
            If Len(dat$) > 48 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
            While Len(dat$) < 48
                dat$ = Chr$(0) + dat$
            Wend
          End If
          If ActELCLenSig >= 64 Then
            If Len(dat$) > 64 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
            While Len(dat$) < 64
                dat$ = Chr$(0) + dat$
            Wend
          End If
          ' Set curve and sign input
          Call ECpSetCurve(ActELCcidSig)
          Call ECpSignDSA(dat$, SigK$, tmp$)
          dat$ = tmp$
      End If
	   ' increment Counter
       TC = Chr$(0) + Counter
	   If TC1 >= &HFFFFFF Then
       SW1SW2 = &H6F00 : Exit Command		' Counter overlow
      Else
        TC1 = TC1 + 1
      End If
      Counter = Right$(TC,3)
      If PW1once = Chr$(0) Then    ' delete PW1-check
         PWchk(1) = 0
      End If

    Case &H8086
        If dat$(1) <> Chr$(0) And dat$(1) <> Chr$(2) And dat$(1) <> Chr$(&HA6) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
        If PWchk(2) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
	    Select Case Asc(dat$(1))
		
			Case &H00
				' RSA Decrypt
				If KeyNrDec = 2 Then
					If DecK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
					If Lc <> ((ActRSALenDec / 8) + 1) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong length
					dat$ = Right$(dat$, Len(dat$) - 1)
					Call RsaExDecryptRaw(dat$, DecK$)
					If dat$(1) <> Chr$(2) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					x = 2
					While Asc(dat$(x)) <> 0
						x = x + 1
						If x > ((ActRSALenDec / 8) - 2) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					Wend
					If x < 9 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					dat$ = Right$(dat$, (ActRSALenDec / 8) - 1 - x)
				Else
					If AutK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
					If Lc <> ((ActRSALenAut / 8) + 1) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong length
					dat$ = Right$(dat$, Len(dat$) - 1)
					Call RsaExDecryptRaw(dat$, AutK$)
					If dat$(1) <> Chr$(2) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					x = 2
					While Asc(dat$(x)) <> 0
						x = x + 1
						If x > ((ActRSALenAut / 8) - 2) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					Wend
					If x < 9 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					dat$ = Right$(dat$, (ActRSALenAut / 8) - 1 - x)
				End If
			
			Case &HA6
				' ELC Decrypt
				If KeyNrDec = 2 Then
					If DecK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
					' Check input DO and extract External PubKey
					tmp$ = TlvGetData(Chr$(&H7F) + Chr$(&H49), dat$, 1)
					If tmp$(1) <> Chr$(&H86) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					dat$ = TlvGetData(Chr$(&H86), tmp$, 1)
					If dat$(1) <> Chr$(&H04) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					dat$ = Right$(dat$, Len(dat$) - 1)
					' Check pubkey lenght
					If ActELCLenDec = 32 And Len(dat$) <> 64 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					If ActELCLenDec = 48 And Len(dat$) <> 96 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					If ActELCLenDec >= 64 And Len(dat$) < 128 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					' Set curve and calculate DH secret
					Call ECpSetCurve(ActELCcidDec)
					tmp$ = "" : Call ECpSharedSecret(DecK$, dat$, tmp$)
					dat$ = tmp$
				Else
					If AutK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
					' Check input DO and extract External PubKey
					tmp$ = TlvGetData(Chr$(&H7F) + Chr$(&H49), dat$, 1)
					If tmp$(1) <> Chr$(&H86) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					dat$ = TlvGetData(Chr$(&H86), tmp$, 1)
					If dat$(1) <> Chr$(&H04) Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					dat$ = Right$(dat$, Len(dat$) - 1)
					' Check pubkey lenght
					If ActELCLenAut = 32 And Len(dat$) <> 64 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					If ActELCLenAut = 48 And Len(dat$) <> 96 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					If ActELCLenAut >= 64 And Len(dat$) < 128 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
					' Set curve and calculate DH secret
					Call ECpSetCurve(ActELCcidAut)
					tmp$ = "" : Call ECpSharedSecret(AutK$, dat$, tmp$)
					dat$ = tmp$
				End If
			
			Case &H02
				' AESKeyPSO Decrypt
				If AESKeyPSO$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
				dat$ = Right$(dat$, Len(dat$) - 1)
				If (Len(dat$) Mod 8) <> 0 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong length
				If Len(AESKeyPSO$) = 16 Then
					Call CryptoDecrypt(AES128Mode, AESKeyPSO$, "", dat$)
				Else
					Call CryptoDecrypt(AES256Mode, AESKeyPSO$, "", dat$)
				End If
			
		End Select

    Case &H8680
        If PWchk(2) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
        ' AESKeyPSO Encrypt
        If AESKeyPSO$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
        If (Lc Mod 8) <> 0 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong length
        If (ExtLe = 0) And (Len(dat$) > 255) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
        If Len(AESKeyPSO$) = 16 Then
          Call CryptoEncrypt(AES128Mode, AESKeyPSO$, "", dat$)
        Else
          Call CryptoEncrypt(AES256Mode, AESKeyPSO$, "", dat$)
        End If
        dat$ = Chr$(2) + dat$

    Case Else
        SW1SW2 = &H6B00 : Exit Command     ' P1/P2 Error

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
  Private tmp$
  Private proto, speed, ExtLe
  If P1P2 <> 0 Then SW1SW2 = &H6B00  : Exit Command	' P1/P2 Error
  If LePresent() = 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command	' Key not found
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  Call CommParams(proto, speed, ExtLe)
  If PWchk(2) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
  If KeyNrAut = 3 Then
    If AutK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
    If ActRSALenAut > 1024 Then
          If (ExtLe = 0) And (ActRSALenAut > 2048) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
          If Lc > ((ActRSALenAut / 8) * 0.4) Then SW1SW2 = &H6985  : Exit Command	' Wrong length
          ' PKCS#1 formatting
          dat$ = Chr$(0) + Chr$(1) + String$((ActRSALenAut / 8) - 3 - Lc, &HFF) + Chr$(0) + dat$
          Call RsaExDecryptRaw(dat$, AutK$)
      Else
         ' Check for valid hash input and fill up if needed
          If ActELCLenAut = 32 Then
            If Len(dat$) > 32 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
            While Len(dat$) < 32
                dat$ = Chr$(0) + dat$
            Wend
          End If
          If ActELCLenAut = 48 Then
            If Len(dat$) > 48 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
            While Len(dat$) < 48
                dat$ = Chr$(0) + dat$
            Wend
          End If
          If ActELCLenAut >=64 Then
            If Len(dat$) > 64 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
            While Len(dat$) < 64
                dat$ = Chr$(0) + dat$
            Wend
          End If
          ' Set curve and sign input
          Call ECpSetCurve(ActELCcidAut)
          Call ECpSignDSA(dat$, AutK$, tmp$)
          dat$ = tmp$
    End If
  Else
    If DecK$ = "" Then SW1SW2 = &H6A88 : Exit Command ' Key not defined
    If ActRSALenDec > 1024 Then
          If (ExtLe = 0) And (ActRSALenDec > 2048) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
          If Lc > ((ActRSALenDec / 8) * 0.4) Then SW1SW2 = &H6985  : Exit Command	' Wrong length
          ' PKCS#1 formatting
          dat$ = Chr$(0) + Chr$(1) + String$((ActRSALenDec / 8) - 3 - Lc, &HFF) + Chr$(0) + dat$
          Call RsaExDecryptRaw(dat$, DecK$)
    Else
         ' Check for valid hash input and fill up if needed
          If ActELCLenDec = 32 Then
            If Len(dat$) > 32 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
            While Len(dat$) < 32
                dat$ = Chr$(0) + dat$
            Wend
          End If
          If ActELCLenDec = 48 Then
            If Len(dat$) > 48 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
            While Len(dat$) < 48
                dat$ = Chr$(0) + dat$
            Wend
          End If
          If ActELCLenDec >=64 Then
            If Len(dat$) > 64 Then SW1SW2 = &H6985  : Exit Command	 ' Wrong Input
            While Len(dat$) < 64
                dat$ = Chr$(0) + dat$
            Wend
          End If
          ' Set curve and sign input
          Call ECpSetCurve(ActELCcidDec)
          Call ECpSignDSA(dat$, DecK$, tmp$)
          dat$ = tmp$
    End If
  End If

  ResponseLength = Len(dat$)
  If Le = 0 Then Le = ResponseLength
  If Le > ResponseLength Then Le = ResponseLength
  If Le < ResponseLength Then dat$ = Left$(dat$, Le)
  SW1SW2 = &H9000
End Command

'
'   GET DATA:
'
'     CLA = 00/0C
'     INS = CA
'     P1  = XX -> BER-TLV tag
'     P2  = XX -> BER-TLV tag
'
Command &H00 &HCA Getdata(dat$)
  Private proto, speed, ExtLe, tmp$
  If LePresent() = 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command   ' DOs not defined
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  Call CommParams(proto, speed, ExtLe)
  If Lc > 0 Then SW1SW2 = &H6700  : Exit Command	' wrong lenght
  If P1P2 <> &H7F21 Then ZertNr = 1
  Select Case P1P2

	Case &H006E
        tmp$ = Chr$(&HC0) + Chr$(10) + ExtCap + Chr$(&HC1) + Chr$(Len(AlgAttrSig)) + AlgAttrSig + Chr$(&HC2) + Chr$(Len(AlgAttrDec)) + AlgAttrDec_
                   + Chr$(&HC3) + Chr$(Len(AlgAttrAut)) + AlgAttrAut + Chr$(&HC4) + Chr$(7) + PWStatus_
                   + Chr$(PWFBZ(1)) + Chr$(RCFBZ) + Chr$(PWFBZ(2))_
                   + Chr$(&HC5) + Chr$(60) + FPSig + FPDec + FPAut_
                   + Chr$(&HC6) + Chr$(60) + CAFP(1) + CAFP(2) + CAFP(3)_
                   + Chr$(&HCD) + Chr$(12) + GenDateSig + GenDateDec + GenDateAut
        dat$ = Chr$(&H4F) + Chr$(16) + AID + Chr$(&H5F) + Chr$(&H52) + Chr$(10) + Historicals + Chr$(&H7F) + Chr$(&H66) + Chr$(08) + ExtLenInf_
                   + Chr$(&H73) + Chr$(&H81) + Chr$(Len(tmp$)) + tmp$

	Case &H00C4
		dat$ = PWStatus + Chr$(PWFBZ(1)) + Chr$(RCFBZ) + Chr$(PWFBZ(2))

	Case &H5F50
      If (ExtLe = 0) And (Len(URL$) > 256) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
		dat$ = URL$

	Case &H5F52
		dat$ = Historicals

	Case &H7F66
		dat$ = ExtLenInf

	Case &H005E
      If (ExtLe = 0) And (Len(LoginData$) > 256) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
		dat$ = LoginData$

	Case &H0065
		dat$ = Chr$(&H5B) + Chr$(Len(UName$)) + UName$ + Chr$(&H5F) + Chr$(&H2D) + Chr$(Len(LangPref$)) + LangPref$_
                   + Chr$(&H5F) + Chr$(&H35) + Chr$(1) + Sex

	Case &H007A
		dat$ = Chr$(&H93) + Chr$(3) + Counter

	Case &H004F
      dat$ = AID

	Case &H0101
      If (ExtLe = 0) And (Len(PU1$) > 256) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
      dat$ = PU1$

	Case &H0102
      If (ExtLe = 0) And (Len(PU2$) > 256) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
      dat$ = PU2$

	Case &H0103
      If PWchk(2) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
      If (ExtLe = 0) And (Len(PU3$) > 256) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
		dat$ = PU3$

	Case &H0104
      If PWchk(3) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
      If (ExtLe = 0) And (Len(PU4$) > 256) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
      dat$ = PU4$

	Case &H7F21
      If (ExtLe = 0) And (Len(Zertifikat(ZertNr)) > 256) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
      dat$ = Zertifikat(ZertNr)

	Case &H00F9
      If (ExtLe = 0) And (Len(KDF$) > 256) Then SW1SW2 = &H6700 : Exit Command	' Le Error, ExtLe expected
		dat$ = KDF$

	Case Else
		SW1SW2 = &H6A88  : Exit Command		' Data not found

  End Select
  ResponseLength = Len(dat$)
  If Le = 0 Then Le = ResponseLength
  If Le > ResponseLength Then Le = ResponseLength
  If Le < ResponseLength Then dat$ = Left$(dat$, Le)
  SW1SW2 = &H9000
End Command

'
'   GET NEXT DATA:
'
'     CLA = 00/0C
'     INS = CC
'     P1  = XX -> BER-TLV tag
'     P2  = XX -> BER-TLV tag
'
Command &H00 &HCC GetNextData(dat$)
  Private proto, speed, ExtLe
  If LePresent() = 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command   ' DOs not defined
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  Call CommParams(proto, speed, ExtLe)
  If Lc > 0 Then SW1SW2 = &H6700  : Exit Command	' wrong lenght
  If P1P2 <> &H7F21 Then ZertNr = 1

  Select Case P1P2

	Case &H7F21
      If ZertNr >= 3 Then
        SW1SW2 = &H6A88
        ZertNr = 1
        Exit Command   ' DO-Instance not defined
      End If
      ZertNr = ZertNr + 1
      If (ExtLe = 0) And (Len(Zertifikat(ZertNr)) > 256) Then
        SW1SW2 = &H6700
        ZertNr = 1
        Exit Command	' Le Error, ExtLe expected
      End If
      dat$ = Zertifikat(ZertNr)

	Case Else
		SW1SW2 = &H6A88  : Exit Command		' Data not found

  End Select

  ResponseLength = Len(dat$)
  If Le = 0 Then Le = ResponseLength
  If Le > ResponseLength Then Le = ResponseLength
  If Le < ResponseLength Then dat$ = Left$(dat$, Le)
  SW1SW2 = &H9000
End Command

'
'   GET DATA odd INS:
'
'     CLA = 00/0C
'     INS = CB
'     P1  = XX -> BER-TLV tag
'     P2  = XX -> BER-TLV tag
'
Command &H00 &HCB GetdataOdd(dat$)
  If LePresent() = 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If Lc <> 2 Then SW1SW2 = &H6700  : Exit Command	' wrong lenght
  If dat$ <> Chr$(&H5C) + Chr$(0) Then SW1SW2 = &H6A80  : Exit Command		' Incorrect parameters in data field
  ZertNr = 1
  Select Case P1P2

	Case &H2F00
		' EF_DIR
		dat$ = Chr$(&H61) + Chr$(&H11) + Chr$(&H4F) + Chr$(6) + Chr$(&HD2) + Chr$(&H76) + Chr$(0) + Chr$(1) + Chr$(&H24) + Chr$(1) + Chr$(&H50) + Chr$(7) + "OpenPGP"

	Case &H2F01
		' EF_ATR/INFO
		dat$ = Chr$(&H7F) + Chr$(&H66) + Chr$(8) + ExtLenInf

	Case Else
		SW1SW2 = &H6A88  : Exit Command		' Data not found

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
'     CLA = 00/0C
'     INS = DA
'     P1  = XX -> BER-TLV tag
'     P2  = XX -> BER-TLV tag
'
Command &H00 &HDA Putdata(dat$)
  Private tmp$
  ' OIDs for ELC
  Private Oansi256 As String*8 = &H2A,&H86,&H48,&HCE,&H3D,&H03,&H01,&H07
  Private Oansi384 As String*5 = &H2B,&H81,&H04,&H00,&H22
  Private Oansi521 As String*5 = &H2B,&H81,&H04,&H00,&H23
  Private Obp256 As String*9 = &H2B,&H24,&H03,&H03,&H02,&H08,&H01,&H01,&H07
  Private Obp384 As String*9 = &H2B,&H24,&H03,&H03,&H02,&H08,&H01,&H01,&H0B
  Private Obp512 As String*9 = &H2B,&H24,&H03,&H03,&H02,&H08,&H01,&H01,&H0D
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command         ' DOs not definined
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  If LePresent() <> 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If (PWchk(3) = 0) And (P1P2 <> &H0101) And (P1P2 <> &H0103) Then SW1SW2 = &H6982 : Exit Command  	' No PW check
  If Lc = 0 Then dat$ = ""
  If P1P2 <> &H7F21 Then ZertNr = 1

  Select Case P1P2

	Case &H005B
        If Lc > 39 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        UName$ = dat$

	Case &H005E
        If Lc > 255 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        LoginData$ = dat$

	Case &H5F2D
        If Lc > 8 Then SW1SW2 = &H6700 : Exit Command          ' wrong lenght
        If (Lc Mod 2) <> 0 Then SW1SW2 = &H6985 : Exit Command	' wrong format
        LangPref$ = dat$

	Case &H5F35
        If Lc <> 1 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        Sex = dat$

	Case &H5F50
        If Lc > 255 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        URL$ = dat$

	Case &H00C1
        If dat$(1) = Chr$(1) And Lc <> 6 Then SW1SW2 = &H6700 : Exit Command	' Wrong lenght
        If dat$(1) <> Chr$(1) And dat$(1) <> Chr$(&H13) Then SW1SW2 = &H6A80 : Exit Command	  ' wrong value
        If dat$(1) = Chr$(1) Then
              If Right$(dat$, 3) <> Chr$(0, &H20, 0) Then SW1SW2 = &H6A80 : Exit Command	' wrong value
              If (Mid$(dat$, 2, 2) <> Chr$(8, 0)) And (Mid$(dat$, 2, 2) <> Chr$(&H0C, 0)) And (Mid$(dat$, 2, 2) <> Chr$(&H10, 0)) Then SW1SW2 = &H6A80 : Exit Command
              If (Asc(dat$(2)) * 256) + (Asc(dat$(3)) Mod 256) <> ActRSALenSig Then
                    Counter = String$(3, 0)
                    FPSig = String$(20,0)
                    GenDateSig = String$(4,0)
                    SigK$ = ""
                    ActRSALenSig = (Asc(dat$(2)) * 256) + (Asc(dat$(3)) Mod 256)
                    ActELCcidSig = 0
                    Zertifikat(3) = ""
                    AlgAttrSig = dat$
             End If
        End If
        If dat$(1) = Chr$(&H13) Then
              If Right$(dat$, 1) = Chr$(&HFF) Then SW1SW2 = &H6A80 : Exit Command	' wrong value
              ' check for valid curves
              If (Mid$(dat$, 2) <> Oansi256) And (Mid$(dat$, 2) <> Oansi384) And (Mid$(dat$, 2) <> Oansi521) And (Mid$(dat$, 2) <> Obp256) And (Mid$(dat$, 2) <> Obp384) And (Mid$(dat$, 2) <> Obp512) Then SW1SW2 = &H6A80 : Exit Command
              If AlgAttrSig <> dat$ Then
                    Counter = String$(3, 0)
                    FPSig = String$(20,0)
                    GenDateSig = String$(4,0)
                    SigK$ = ""
                    Zertifikat(3) = ""
                    ActRSALenSig = 0
                    If Mid$(dat$, 2) = Oansi256 Then ActELCcidSig = P256 : ActELCLenSig = 32
                    If Mid$(dat$, 2) = Oansi384 Then ActELCcidSig = P384 : ActELCLenSig = 48
                    If Mid$(dat$, 2) = Oansi521 Then ActELCcidSig = P521 : ActELCLenSig = 66
                    If Mid$(dat$, 2) = Obp256 Then ActELCcidSig = BP256 : ActELCLenSig = 32
                    If Mid$(dat$, 2) = Obp384 Then ActELCcidSig = BP384 : ActELCLenSig = 48
                    If Mid$(dat$, 2) = Obp512 Then ActELCcidSig = BP512 : ActELCLenSig = 64
                    AlgAttrSig = dat$
              End If
        End If

	Case &H00C2
        If dat$(1) = Chr$(1) And Lc <> 6 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        If dat$(1) <> Chr$(1) And dat$(1) <> Chr$(&H12) Then SW1SW2 = &H6A80 : Exit Command	  ' wrong value
        If dat$(1) = Chr$(1) Then
              If Right$(dat$, 3) <> Chr$(0, &H20, 0) Then SW1SW2 = &H6A80 : Exit Command	' wrong value
              If (Mid$(dat$, 2, 2) <> Chr$(8, 0)) And (Mid$(dat$, 2, 2) <> Chr$(&H0C, 0)) And (Mid$(dat$, 2, 2) <> Chr$(&H10, 0)) Then SW1SW2 = &H6A80 : Exit Command
              If (Asc(dat$(2)) * 256) + (Asc(dat$(3)) Mod 256) <> ActRSALenDec Then
                    FPDec = String$(20,0)
                    GenDateDec = String$(4,0)
                    DecK$ = ""
                    ActRSALenDec = (Asc(dat$(2)) * 256) + (Asc(dat$(3)) Mod 256)
                    ActELCcidDec = 0
                    Zertifikat(2) = ""
                    AlgAttrDec = dat$
              End If
        End If
        If dat$(1) = Chr$(&H12) Then
              If Right$(dat$, 1) = Chr$(&HFF) Then SW1SW2 = &H6A80 : Exit Command	' wrong value
              ' check for valid curves
              If (Mid$(dat$, 2) <> Oansi256) And (Mid$(dat$, 2) <> Oansi384) And (Mid$(dat$, 2) <> Oansi521) And (Mid$(dat$, 2) <> Obp256) And (Mid$(dat$, 2) <> Obp384) And (Mid$(dat$, 2) <> Obp512) Then SW1SW2 = &H6A80 : Exit Command
              If AlgAttrDec <> dat$ Then
                    FPDec = String$(20,0)
                    GenDateDec = String$(4,0)
                    DecK$ = ""
                    Zertifikat(2) = ""
                    ActRSALenDec = 0
                    If Mid$(dat$, 2) = Oansi256 Then ActELCcidDec = P256 : ActELCLenDec = 32
                    If Mid$(dat$, 2) = Oansi384 Then ActELCcidDec = P384 : ActELCLenDec = 48
                    If Mid$(dat$, 2) = Oansi521 Then ActELCcidDec = P521 : ActELCLenDec = 66
                    If Mid$(dat$, 2) = Obp256 Then ActELCcidDec = BP256 : ActELCLenDec = 32
                    If Mid$(dat$, 2) = Obp384 Then ActELCcidDec = BP384 : ActELCLenDec = 48
                    If Mid$(dat$, 2) = Obp512 Then ActELCcidDec = BP512 : ActELCLenDec = 64
                    AlgAttrDec = dat$
              End If
        End If

	Case &H00C3
        If dat$(1) = Chr$(1) And Lc <> 6 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        If dat$(1) <> Chr$(1) And dat$(1) <> Chr$(&H13) Then SW1SW2 = &H6A80 : Exit Command	  ' wrong value
        If dat$(1) = Chr$(1) Then
              If Right$(dat$, 3) <> Chr$(0, &H20, 0) Then SW1SW2 = &H6A80 : Exit Command	' wrong value
              If (Mid$(dat$, 2, 2) <> Chr$(8, 0)) And (Mid$(dat$, 2, 2) <> Chr$(&H0C, 0)) And (Mid$(dat$, 2, 2) <> Chr$(&H10, 0)) Then SW1SW2 = &H6A80 : Exit Command
              If (Asc(dat$(2)) * 256) + (Asc(dat$(3)) Mod 256) <> ActRSALenAut Then
                    FPAut = String$(20,0)
                    GenDateAut = String$(4,0)
                    AutK$ = ""
                    ActRSALenAut = (Asc(dat$(2)) * 256) + (Asc(dat$(3)) Mod 256)
                    ActELCcidAut = 0
                    Zertifikat(1) = ""
                    AlgAttrAut = dat$
              End If
        End If
        If dat$(1) = Chr$(&H13) Then
              If Right$(dat$, 1) = Chr$(&HFF) Then SW1SW2 = &H6A80 : Exit Command	' wrong value
              ' check for valid curves
              If (Mid$(dat$, 2) <> Oansi256) And (Mid$(dat$, 2) <> Oansi384) And (Mid$(dat$, 2) <> Oansi521) And (Mid$(dat$, 2) <> Obp256) And (Mid$(dat$, 2) <> Obp384) And (Mid$(dat$, 2) <> Obp512) Then SW1SW2 = &H6A80 : Exit Command
              If AlgAttrAut <> dat$ Then
                    FPAut = String$(20,0)
                    GenDateAut = String$(4,0)
                    AutK$ = ""
                    Zertifikat(1) = ""
                    ActRSALenAut = 0
                    If Mid$(dat$, 2) = Oansi256 Then ActELCcidAut = P256 : ActELCLenAut = 32
                    If Mid$(dat$, 2) = Oansi384 Then ActELCcidAut = P384 : ActELCLenAut = 48
                    If Mid$(dat$, 2) = Oansi521 Then ActELCcidAut = P521 : ActELCLenAut = 66
                    If Mid$(dat$, 2) = Obp256 Then ActELCcidAut = BP256 : ActELCLenAut = 32
                    If Mid$(dat$, 2) = Obp384 Then ActELCcidAut = BP384 : ActELCLenAut = 48
                    If Mid$(dat$, 2) = Obp512 Then ActELCcidAut = BP512 : ActELCLenAut = 64
                    AlgAttrAut = dat$
              End If
        End If

	Case &H00C4
        If Lc <> 1 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        If (dat$ <> Chr$(0)) And (dat$ <> Chr$(1)) Then SW1SW2 = &H6A88 : Exit Command    ' DO not defined
        PW1once = dat$

	Case &H00C7
        If Lc <> 20 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        FPSig = dat$

	Case &H00C8
        If Lc <> 20 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        FPDec = dat$

	Case &H00C9
        If Lc <> 20 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        FPAut = dat$

	Case &H00CA
        If Lc <> 20 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        CAFP(1) = dat$

	Case &H00CB
        If Lc <> 20 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        CAFP(2) = dat$

	Case &H00CC
        If Lc <> 20 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        CAFP(3) = dat$

    Case &H00CE
      If Lc <> 4 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
      GenDateSig = dat$

    Case &H00CF
      If Lc <> 4 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
      GenDateDec = dat$

    Case &H00D0
      If Lc <> 4 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
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
          If Lc <> 16 And Lc <> 32 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
          AESKeyPSO$ = dat$

    Case &H7F21
          Zertifikat(ZertNr) = dat$

    Case &H0101
        If PWchk(2) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
        If Lc > 255 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        PU1$ = dat$

	Case &H0102
        If Lc > 255 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        PU2$ = dat$

	Case &H0103
        If PWchk(2) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
        If Lc > 255 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        PU3$ = dat$

	Case &H0104
        If Lc > 255 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        PU4$ = dat$

	Case &H00F9
        If Lc > 255 Then SW1SW2 = &H6700 : Exit Command	' wrong lenght
        KDF$ = dat$

	Case Else
		SW1SW2 = &H6A88  : Exit Command		' DO not defined

  End Select
  dat$ = "" : SW1SW2 = &H9000
End Command

'
'   PUT DATA:       ODD INS for Key-Import
'
'     CLA = 00/0C
'     INS = DB
'     P1  = 3F
'     P2  = FF
'
Command &H00 &HDB PutdataOdd(dat$)
  Private Keyref, p$, e$
  Private Check2048 As String*16 = &H7F,&H48,&H08,&H91,&H04,&H92,&H81,&H80,&H93,&H81,&H80,&H5F,&H48,&H82,&H01,&H04
  Private Check3072 As String*16 = &H7F,&H48,&H08,&H91,&H04,&H92,&H81,&HC0,&H93,&H81,&HC0,&H5F,&H48,&H82,&H01,&H84
  Private Check4096 As String*18 = &H7F,&H48,&H0A,&H91,&H04,&H92,&H82,&H01,&H00,&H93,&H82,&H01,&H00,&H5F,&H48,&H82,&H02,&H04
  Private Check256 As String*8 = &H7F,&H48,&H02,&H92,&H20,&H5F,&H48,&H20
  Private Check384 As String*8 = &H7F,&H48,&H02,&H92,&H30,&H5F,&H48,&H30
  Private Check512 As String*8 = &H7F,&H48,&H02,&H92,&H40,&H5F,&H48,&H40
  Private Check521 As String*8 = &H7F,&H48,&H02,&H92,&H42,&H5F,&H48,&H42
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command         ' DOs not defined
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  If P1P2 <> &H3FFF Then SW1SW2 = &H6B00  : Exit Command	' P1/P2 Error
  If PWchk(3) = 0 Then SW1SW2 = &H6982 : Exit Command  	' No PW check
  If Left$(dat$, 1) <> Chr$(&H4D) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
  If Mid$(dat$, 2, 1) = Chr$(&H82) Then
      If Mid$(dat$, 3, 2) <> Chr$((Lc - 4) / 256) + Chr$((Lc - 4) mod 256) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
  Else
      If Mid$(dat$, 2, 1) = Chr$(&H81) Then
        If Mid$(dat$, 3, 1) <> Chr$(Lc - 3) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
      Else
        If Mid$(dat$, 2, 1) <> Chr$(Lc - 2) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
      End If
  End If
  If Instr(2, Left$(dat$, 10), Chr$(&HB6) + Chr$(0)) > 0 Then Keyref = &HB6
  If Instr(2, Left$(dat$, 10), Chr$(&HB8) + Chr$(0)) > 0 Then Keyref = &HB8
  If Instr(2, Left$(dat$, 10), Chr$(&HA4) + Chr$(0)) > 0 Then Keyref = &HA4
  If Instr(2, Left$(dat$, 10), Chr$(&H7F) + Chr$(&H48)) > 0 Then
     dat$ = Mid$(dat$, Instr(2, Left$(dat$, 10), Chr$(&H7F) + Chr$(&H48)))
  Else
    SW1SW2 = &H6A80 	' Wrong parameter in data
    Exit Command
  End If

  ZertNr = 1

  Select Case Keyref

	Case &HB6
      If ActRSALenSig > 1024 Then
          If (ActRSALenSig = 2048) And (Left$(dat$, 16) <> Check2048) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If (ActRSALenSig = 3072) And (Left$(dat$, 16) <> Check3072) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If (ActRSALenSig = 4096) And (Left$(dat$, 18) <> Check4096) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActRSALenSig = 2048 Then dat$ = Right$(dat$, 260) : If Len(dat$) <> 260 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActRSALenSig = 3072 Then dat$ = Right$(dat$, 388) : If Len(dat$) <> 388 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActRSALenSig = 4096 Then dat$ = Right$(dat$, 516) : If Len(dat$) <> 516 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          ' store e
          e$ = Left$(dat$, 4) : dat$ = Right$(dat$, Len(dat$) - 4)
          ' store p
          p$ = Left$(dat$, ActRSALenSig / 16)
          ' Rest of dat$ is q
          dat$ = Right$(dat$, ActRSALenSig / 16)
          ' Calculate new CRT-Key from p, q and e
          Call RsaExConstructKey (p$, dat$, e$, SigK$)
      Else
          If ActELCLenSig = 32 And Left$(dat$, 8) <> Check256 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenSig = 48 And Left$(dat$, 8) <> Check384 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenSig = 64 And Left$(dat$, 8) <> Check512 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenSig = 66 And Left$(dat$, 8) <> Check521 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenSig = 32 Then dat$ = Right$(dat$, &H20) : If Len(dat$) <> &H20 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenSig = 48 Then dat$ = Right$(dat$, &H30) : If Len(dat$) <> &H30 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenSig = 66 Then dat$ = Right$(dat$, &H42) : If Len(dat$) <> &H42 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenSig = 64 Then dat$ = Right$(dat$, &H40) : If Len(dat$) <> &H40 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          SigK$ = dat$
      End If
      ' Clear relevant DOs
      Counter = String$(3,0)
      FPSig = String$(20,0)
      GenDateSig = String$(4,0)
      Zertifikat(3) = ""

	Case &HB8
      If ActRSALenDec > 1024 Then
          If (ActRSALenDec = 2048) And (Left$(dat$, 16) <> Check2048) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If (ActRSALenDec = 3072) And (Left$(dat$, 16) <> Check3072) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If (ActRSALenDec = 4096) And (Left$(dat$, 18) <> Check4096) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActRSALenDec = 2048 Then dat$ = Right$(dat$, 260) : If Len(dat$) <> 260 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActRSALenDec = 3072 Then dat$ = Right$(dat$, 388) : If Len(dat$) <> 388 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActRSALenDec = 4096 Then dat$ = Right$(dat$, 516) : If Len(dat$) <> 516 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          ' store e
          e$ = Left$(dat$, 4) : dat$ = Right$(dat$, Len(dat$) - 4)
          ' store p
          p$ = Left$(dat$, ActRSALenDec / 16)
          ' Rest of dat$ is q
          dat$ = Right$(dat$, ActRSALenDec / 16)
          ' Calculate new CRT-Key from p, q and e
          Call RsaExConstructKey (p$, dat$, e$, DecK$)
      Else
          If ActELCLenDec = 32 And Left$(dat$, 8) <> Check256 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenDec = 48 And Left$(dat$, 8) <> Check384 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenDec = 64 And Left$(dat$, 8) <> Check512 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenDec = 66 And Left$(dat$, 8) <> Check521 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenDec = 32 Then dat$ = Right$(dat$, &H20) : If Len(dat$) <> &H20 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenDec = 48 Then dat$ = Right$(dat$, &H30) : If Len(dat$) <> &H30 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenDec = 66 Then dat$ = Right$(dat$, &H42) : If Len(dat$) <> &H42 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenDec = 64 Then dat$ = Right$(dat$, &H40) : If Len(dat$) <> &H40 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          DecK$ = dat$
      End If
      ' Clear relevant DOs
        FPDec = String$(20,0)
        GenDateDec = String$(4,0)
        Zertifikat(2) = ""

	Case &HA4
      If ActRSALenAut > 1024 Then
          If (ActRSALenAut = 2048) And (Left$(dat$, 16) <> Check2048) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If (ActRSALenAut = 3072) And (Left$(dat$, 16) <> Check3072) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If (ActRSALenAut = 4096) And (Left$(dat$, 18) <> Check4096) Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActRSALenAut = 2048 Then dat$ = Right$(dat$, 260) : If Len(dat$) <> 260 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActRSALenAut = 3072 Then dat$ = Right$(dat$, 388) : If Len(dat$) <> 388 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActRSALenAut = 4096 Then dat$ = Right$(dat$, 516) : If Len(dat$) <> 516 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          ' store e
          e$ = Left$(dat$, 4) : dat$ = Right$(dat$, Len(dat$) - 4)
          ' store p
          p$ = Left$(dat$, ActRSALenAut / 16)
          ' Rest of dat$ is q
          dat$ = Right$(dat$, ActRSALenAut / 16)
          ' Calculate new CRT-Key from p, q and e
          Call RsaExConstructKey (p$, dat$, e$, AutK$)
      Else
          If ActELCLenAut = 32 And Left$(dat$, 8) <> Check256 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenAut = 48 And Left$(dat$, 8) <> Check384 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenAut = 64 And Left$(dat$, 8) <> Check512 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenAut = 66 And Left$(dat$, 8) <> Check521 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenAut = 32 Then dat$ = Right$(dat$, &H20) : If Len(dat$) <> &H20 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenAut = 48 Then dat$ = Right$(dat$, &H30) : If Len(dat$) <> &H30 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenAut = 66 Then dat$ = Right$(dat$, &H42) : If Len(dat$) <> &H42 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          If ActELCLenAut = 64 Then dat$ = Right$(dat$, &H40) : If Len(dat$) <> &H40 Then SW1SW2 = &H6A80  : Exit Command	' Wrong parameter in data
          AutK$ = dat$
      End If
      ' Clear relevant DOs
        FPAut = String$(20,0)
        GenDateAut = String$(4,0)
        Zertifikat(1) = ""

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
  LCS = Chr$(&H03)    ' LifeCycleStatus to Initialisation state
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

'
'   MANAGE SECURITY ENVIRONMENT:
'
'     CLA = 00
'     INS = 22
'     P1  = 41 SET
'     P2  = A4 (Authentication) / B8 (Confidentiality)
'
Command &H00 &H22 MSE(dat$)
  Private tmpKeyNr
  If AppSel = 0 Then SW1SW2 = &H6A88 : Exit Command   ' App not selected
  If LCS <> Chr$(&H05) Then SW1SW2 = &H6285 : Exit Command  ' App terminated
  If P1 <> &H41 Then SW1SW2 = &H6B00 : Exit Command   ' P1/P2 Error
  If (P2 <> &HA4) And (P2 <> &HB8) Then SW1SW2 = &H6B00 : Exit Command ' P1/P2 Error
  If Lc <> 3 Then SW1SW2 = &H6700 : Exit Command	      ' Lc Error
  If LePresent() <> 0 Then SW1SW2 = &H6700 : Exit Command ' Le error
  If Left$(dat$, 2) <> Chr$(&H83) + Chr$(1) Then SW1SW2 = &H6A80 : Exit Command ' Wrong DO
  tmpKeyNr = Asc(Mid$(dat$, 3, 1))
  If (tmpKeyNr <> 2) And (tmpKeyNr <> 3) Then SW1SW2 = &H6A88 : Exit Command ' Wrong KeyRef
  If P2 = &HA4 Then
      KeyNrAut = tmpKeyNr
  Else
      KeyNrDec = tmpKeyNr
  End If
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
