---------------------------------------------------------------------
キーワード1
#include #define #pragma #ifndef #ifdef #endif #error #undef #line #else #elif #if and_eq auto and asm bitand bitor break bool const_cast continue code_seg const catch class case char dynamic_cast default defined disable double delete do explicit export extern else enum friend false float for goto init_seg inline int if long mutable namespace not_eq new not operator or_eq once or protected private public reinterpret_cast register return static_cast signed sizeof static struct switch short template typename typedef typeid throw this true try unsigned union using volatile virtual void wchar_t warning while xor_eq xor

キーワード2

対応括弧
半角
(qqwwqq)
<>（HTMLのみ）
｢｣ 
[ffffffffffffff]
{}

全角
（）
〈〉
《》
『』
［］
｛｝
【】


URL/メールアドレス
test@megasoft.co.jp
https://www.megasoft.co.jp
---------------------------------------------------------------------

#include "xmiw.h"
#include "Shellapi.h"
#include <assert.h>

#ifdef __MSVC__
 #ifdef USE_CAT
  #ifdef STDCPP
  #endif
 #endif
#elif define(GCC)
 #ifdef USE_DOG
  #ifdef STDCPP2
  #endif
 #endif
#else
 #ifdef USE_FISH
  #ifdef STDCPP3
  #endif
 #endif
#endif

const char* STRING0 = "";
const char* STRING1 = '';
const char* STRING2 = "test";
const char* STRING3 = 'テスト';
const char* STRING4 = "エスケープ\"エスケープ";
const char* STRING5 = 'エスケープ\"エスケープ';
const char* STRING6 = """";
const char* STRING6 = "''";
const char* STRING6 = L"''";
const char* STRING6 = L'aaa\aaa\aaa';

/* multimon.h からの抜粋	*/
#define SM_XVIRTUALSCREEN	76
#define	SM_YVIRTUALSCREEN	77
#define	SM_CXVIRTUALSCREEN	78
#define	SM_CYVIRTUALSCREEN	79
#define	SM_CMONITORS		80
#define MONITOR_DEFAULTTONULL       0x00000000
#define MONITOR_DEFAULTTOPRIMARY    0x00000001
#define MONITOR_DEFAULTTONEAREST    0x00000002
#define MONITORINFOF_PRIMARY        0x00000001
struct MONITORINFO {
    DWORD   cbSize;
    RECT    rcMonitor;
    RECT    rcWork;
    DWORD   dwFlags;
} ;



/* 保存時のﾃﾞﾌｫﾙﾄのﾌｧｲﾙ名を得る 				*/
/*   ﾃﾞﾌｫﾙﾄのﾌｫﾙﾀﾞ名のﾊﾞｲﾄ数を関数値に返す			*/
/*    関数値：  0=ﾌｧｲﾙ名未定のｳｨﾝﾄﾞｳ(pathのみ有効)		*/
/*              1=ﾌｧｲﾙ名が確定したｳｨﾝﾄﾞｳ(pathとdirの両方が有効)	*/
INT32 getdeffnam(int dummy,byte,dummy2,
 BYTE *path,	/* ﾃﾞﾌｫﾙﾄのﾌｧｲﾙ名を返すﾊﾞｯﾌｧ(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
 BYTE *dir)	/* ﾃﾞﾌｫﾙﾄのﾌｫﾙﾀﾞ名を返すﾊﾞｯﾌｧ(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
{
	INT32 i;
	BYTE *p,*q;

	if( mp->newflg == 0 ) {		/* ﾌｧｲﾙ名が確定したｳｨﾝﾄﾞｳ */
		q = getfnamp(mp->outfile);
		fstrcpy(path,q);
		fstrcpy(dir,mp->outfile);
		dir[(INT32)(q-mp->outfile)] = '\0';
		return(1);
	}
	else if( mp->newflg >= 3 ) {	/* ｸﾞﾛｰﾊﾞﾙ検索結果/一括ﾌｧｲﾙ比較結果/DOSｼｪﾙｴｽｹｰﾌﾟ */
		for( q=path,p=mp->outfile,i=0 ; *p && i < 64 ; ) {
			if( ctypesjis[*p]&CASCII ) {
				if( *p == 0x20 )
					p++;
				else if( ctypej[*p]&CFNAM ) {
					*q++ = *p++;
					i++;
				}
				else
					p++;
			}
			else if( ctypesjis[*p]&CKANJI1 ) {
				*q++ = *p++;
				*q++ = *p++;
				i += 2;
			}
			else if( ctypesjis[*p]&CUNIMARK ) {
				if( *p == UCS2MARK ) {
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
					i += 3;
				}
				else		/* UCS-4はﾌｧｲﾙ名には不適当と見なす */
					p += 5;
			}
			else
				p++;
		}
		*q = '\0';
		return(0);
	}
	else {			/* ﾌｧｲﾙ名が未定のｳｨﾝﾄﾞｳ --- ﾌｧｲﾙの先頭付近の内容からﾌｧｲﾙ名を得る */
		gettopline(path,64);
		return(0);
	}
}

INT32 gettopline(q0,max)	/* ｶﾚﾝﾄﾌｧｲﾙの先頭付近からﾃﾞﾌｫﾙﾄのﾌｧｲﾙ名とする文字列を得る */
BYTE *q0;	/* 得られた文字列(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
INT32 max;	/* 得られた文字列の最大ﾊﾞｲﾄ数（終端のﾇﾙｺｰﾄﾞを除いたﾊﾞｲﾄ数）*/
{
	INT32 i;
	BYTE *p,*q,*pp,buff[BLKSSIZE];

	if( mp->eforblks > 0 ) {
		i = getblks(buff,0,0,1);
		p = buff;
		pp = &buff[i];	/* i=BLKSSIZE */
	}
	else {
		p = mp->ebuffp;
		pp = mp->ebuffep;
	}
	for( q=q0,i=0 ; p < pp && i < max ; ) {
		if( *p == RECMARK ) {
			if( i > 0 )
				break;
			p += INFOSIZE1;
		}
		else if( *p == BINMARK )
			p += 2;
		else if( ctypex[*p]&CUNIMARK ) {
			if( *p == UCS2MARK ) {
				*q++ = *p++;
				*q++ = *p++;
				*q++ = *p++;
				i += 3;
			}
			else		/* UCS-4はﾌｧｲﾙ名には不適当と見なす */
				p += 5;
		}
		else if( ctypex[*p]&CKANJI1 ) {
			if( spacechar(p) ) {	/* 全角ｽﾍﾟｰｽ */
				if( i > 0 ) {
					*q++ = *p++;
					*q++ = *p++;
					i += 2;
				}
				else
					p += 2;
			}
			else if( zkeichar(p) ) {/* 罫線文字は無視 */
				p += 2;
			}
			else {			/* 一般漢字 */
				*q++ = *p++;
				*q++ = *p++;
				i += 2;
			}
		}
		else if( ctypex[*p]&CASCII ) {
			if( *p == '\\' || *p == '/' ) {
				q = q0;
				i = 0;
				p++;
			}
			else if( *p == 0x20 ) {
				if( i > 0 ) {
					*q++ = *p++;
					i++;
				}
				else
					p++;
			}
			else if( ctypej[*p]&CFNAM ) {	/* ﾌｧｲﾙ名に有効な文字 */
				*q++ = *p++;
				i++;
			}
			else
				p++;
		}
		else {		/* ﾀﾌﾞｺｰﾄﾞ */
			p++;
		}
	}
	*q = '\0';
	return((INT32)(q-q0));
}

/*「明示ｷｰﾜｰﾄﾞの追加・変更」ﾘｽﾄの項目文字列を取得する */
INT32 getkwditem(buff,id)
BYTE *buff;
INT32 id;
{
	INT32 i;

	if( id < DEFKWDMAX ) {	/* ﾃﾞﾌｫﾙﾄの明示ｷｰﾜｰﾄﾞ定義 */
		if( id == DEFKWDID1 )		/* <JavaScript> */
			i = getpartstr(1377,1,buff,32);
		else if( id == DEFKWDID2 )	/* その他の全てのﾌｧｲﾙ */
			i = getpartstr(1377,2,buff,32);
		else
			i = getpartstr(1376,3+id,buff,32);
		if( id != DEFKWDID2 )	/* その他の全てのﾌｧｲﾙ以外 */
			i += fstrcpy(buff+i,ppmac->keywdex[id]);
	}
	else if( ppmac->keywdid[id]&0x0001 ) {
		if( ppmac->keywdex[id][0] == '<' )
			i = getpartstr(1377,1,buff,32);
		else
			i = getpartstr(1377,0,buff,32);
		i += fstrcpy(buff+i,ppmac->keywdex[id]);
	}
	else {
		i = getpartstr(1377,5,buff,32);
	}
	return(i);
}

/*「明示ｷｰﾜｰﾄﾞの定義変更」ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽにおいて、「HTMLﾀｲﾌﾟの認識にする」に関連する項目をｾｯﾄする */
void setctrltag(hdlg,flag)
HWND hdlg;
INT32 flag;
{
	BOOL allbool,vbsbool;

	if( flag ) {	/* 「HTMLﾀｲﾌﾟの認識にする」ON */
		allbool = FALSE;
		vbsbool = TRUE;
		if( flag >= 2 ) {
			SendDlgItemMessage(hdlg,IDD_KEYWDRE2,BM_SETCHECK,0,0);
			SendDlgItemMessage(hdlg,IDD_KEYWDRE3,BM_SETCHECK,0,0);
			SendDlgItemMessage(hdlg,IDD_KEYWDRE4,BM_SETCHECK,0,0);
			if( flag == 3 )
				goto noregex;
			SetDlgItemText(hdlg,IDD_KEYWDC1,"");
			SetDlgItemText(hdlg,IDD_KEYWDC2,"<!--");
			SetDlgItemText(hdlg,IDD_KEYWDC3,"-->");
			if( GetDlgItem(hdlg,IDD_KEYWDNST) )
				SendDlgItemMessage(hdlg,IDD_KEYWDNST,BM_SETCHECK,0,0);
			SendDlgItemMessage(hdlg,IDD_KEYWDIFD,BM_SETCHECK,0,0);
			SendDlgItemMessage(hdlg,IDD_KEYWDIFN,BM_SETCHECK,0,0);
			SendDlgItemMessage(hdlg,IDD_KEYWDKWD,BM_SETCHECK,1,0);
			SendDlgItemMessage(hdlg,IDD_KEYWDURL,BM_SETCHECK,1,0);
			SendDlgItemMessage(hdlg,IDD_KEYWDSTRD,BM_SETCHECK,1,0);
			SendDlgItemMessage(hdlg,IDD_KEYWDSTRS,BM_SETCHECK,1,0);
		}
	}
	else {		/* 「HTMLﾀｲﾌﾟの認識にする」OFF */
		allbool = TRUE;
		vbsbool = FALSE;
	}
	EnableWindow(GetDlgItem(hdlg,IDD_KEYWDVBS),vbsbool);
	EnableWindow(GetDlgItem(hdlg,IDD_KEYWDC1),allbool);
	EnableWindow(GetDlgItem(hdlg,IDD_KEYWDC2),allbool);
	EnableWindow(GetDlgItem(hdlg,IDD_KEYWDC3),allbool);
	if( GetDlgItem(hdlg,IDD_KEYWDNST) )
		EnableWindow(GetDlgItem(hdlg,IDD_KEYWDNST),allbool);
	EnableWindow(GetDlgItem(hdlg,IDD_KEYWDKWD),allbool);
	EnableWindow(GetDlgItem(hdlg,IDD_KEYWDURL),allbool);
	EnableWindow(GetDlgItem(hdlg,IDD_KEYWDSTRD),allbool);
	EnableWindow(GetDlgItem(hdlg,IDD_KEYWDSTRS),allbool);
	noregex:
	EnableWindow(GetDlgItem(hdlg,IDD_KEYWDRE2),allbool);
	EnableWindow(GetDlgItem(hdlg,IDD_KEYWDRE3),allbool);
	EnableWindow(GetDlgItem(hdlg,IDD_KEYWDRE4),allbool);
	EnableWindow(GetDlgItem(hdlg,IDD_KEYWDREG),allbool);
}

INT32 regsize(buff,col,size)
BYTE *buff;
INT32 col;
DWORD size;
{
	INT32 i;
	BYTE *p,flag;
	DWORD n;

	flag = 0;
	p = buff+((col==0)?32:col);
	retry:
	*p = '\0';
	if( flag == 0 )
		n = size;
	else if( flag == 1 ) {
		*(--p) = 'K';
		n = ((size/1024)+((size%1024)?1:0));
	}
	else if( flag == 2 ) {
		*(--p) = 'M';
		n = ((size/(1024*1024))+((size%(1024*1024))?1:0));
	}
	else {
		*(--p) = 'G';
		n = ((size/(1024*1024*1024))+((size%(1024*1024*1024))?1:0));
	}
	for( i = 0 ; ; ) {
		if( p <= buff ) {
			flag++;
			p = buff+col;
			goto retry;
		}
		if( i == 3 || i == 6 || i == 9 )
			*(--p) = ',';
		if( p <= buff ) {
			flag++;
			p = buff+col;
			goto retry;
		}
		*(--p) = (BYTE)((n%10)+'0');
		i++;
		n /= 10;
		if( n == 0 )
			break;
	}
	if( col == 0 ) {
		for( i = 0 ; *p ; i++ )
			*buff++ = *p++;
		*buff = '\0';
		return(i);
	}
	else {
		for( ; p > buff ; )
			*(--p) = ' ';
		return(col);
	}
}

void disppathdlg(hdlg,id,path)		/* ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽ中にﾊﾟｽ名/ﾌｫﾙﾀﾞｰ名を表示(必要な省略して表示) */
HWND hdlg;	/* ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽ */
INT32 id;	/* ｺﾝﾄﾛｰﾙのID */
BYTE *path;	/* 表示するﾊﾟｽ名/ﾌｫﾙﾀﾞｰ名 */
{
	RECT rc;
	BYTE buff[PATHSIZE];

	getfontwid(hdlg,id,NULL);
	GetClientRect(GetDlgItem(hdlg,id),&rc);
	getabpath(buff,path,0x00,rc.right-rc.left-4,dlgfwid);
	setdlgitemtextM(hdlg,id,buff);
}

/* ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽ中に省略ﾌｧｲﾙ名/ﾊﾟｽ名を表示するための準備		*/
/* ﾀﾞｲｱﾛｸﾞ中の指定のｺﾝﾄﾛｰﾙで使用しているﾌｫﾝﾄの文字幅ﾃｰﾌﾞﾙを得る	*/
INT32 getfontwid(hdlg,id,widfont)
HWND hdlg;	/* ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽ */
DWORD id;	/* ｺﾝﾄﾛｰﾙのID */
BYTE *widfont;	/* 文字幅ﾃｰﾌﾞﾙ([256])を返すﾊﾞｯﾌｧ */
		/* 通常はNULL→dlgfwid[]に返す */
{
	INT32 i,wid[100];
	HFONT hf,hfold;
	SIZE sz;
	HDC thdc;

	if( widfont == NULL ) {
		if( dlgfwid['C'] > 0 )	/* ﾃﾞﾌｫﾙﾄﾌｫﾝﾄの文字幅ﾃｰﾌﾞﾙはすでに設定済み */
			return(0);
		widfont = dlgfwid;
	}
	hf = (HFONT)SendDlgItemMessage(hdlg,id,WM_GETFONT,0,0);
	if( hf == NULL )
		hf = GetStockObject(DEFAULT_GUI_FONT);
	thdc = GetDC(NULL);
	hfold = SelectObject(thdc,hf);
	GetCharWidth(thdc,32,128,(LPINT)wid);
	for( i = 32 ; i <= 128 ; i++ )		/* ANSI */
		*(widfont+i) = (BYTE)wid[i-32];
	GetCharWidth(thdc,160,223,(LPINT)wid);
	for( i = 160 ; i <= 223 ; i++ )		/* 半角ｶﾅ */
		*(widfont+i) = (BYTE)wid[i-160];
	GetTextExtentPoint32(thdc,"検索結果",8,&sz);
	*(widfont+252) = (BYTE)(sz.cx/4);	/* 全角1文字の横幅 */
	*(widfont+253) = (BYTE)(sz.cy);		/* 全角4文字の横幅 */
	SelectObject(thdc,hfold);
	ReleaseDC(NULL,thdc);
	return(1);
}

INT32 getxsize(p,wid)	/* ﾌｧｲﾙ名/ﾊﾟｽ名の表示文字幅(ﾋﾟｸｾﾙ数)を計算する */
BYTE *p;	/* ﾌｧｲﾙ名/ﾊﾟｽ名(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
BYTE *wid;	/* 文字幅ﾃｰﾌﾞﾙ[256] --- [0x20]～[0x80],[0xa0]～[0xdf],[252]だけが有効	*/
		/*                      [252]が全角1文字の横幅				*/
{
	INT32 x,x1,x2;

	x1 = (INT32)(*(wid+'C'));
	x2 = (INT32)(*(wid+252));	/* 漢字1文字の横幅 */
	for( x = 0 ; *p ; ) {		/* ﾊﾟｽ名の表示幅を計算する */
		if( ctypesjis[*p]&CASCII ) {
			x += (INT32)(*(wid+(INT32)*p));
			p++;
		}
		else if( ctypesjis[*p]&CKANJI1 ) {
			x += x2;
			p += 2;
		}
		else if( ctypesjis[*p]&CUNIMARK ) {
			if( getucscol(p) == 2 )	/* 全角UCS-2、UCS-4 */
				x += x2;
			else			/* 半角UCS-2 */
				x += x1;
			if( *p == UCS2MARK )
				p += 3;
			else
				p += 5;
		}
		else		/* ﾇﾙｺｰﾄﾞ/ﾀﾌﾞｺｰﾄﾞ/制御ｺｰﾄﾞ */
			break;
	}
	return(x);
}

/* ﾊﾟｽ名/ﾌｧｲﾙ名の省略(一般文字列の省略も可能)				*/
/* 関数値には省略前のﾊﾟｽ名/ﾌｧｲﾙ名の最終位置(通常はﾇﾙｺｰﾄﾞの位置)を返す	*/
BYTE * getabpath(p1,p0,flag,xsize,wid)
BYTE *p1;	/* 省略したﾊﾟｽ名を返すﾊﾞｯﾌｧ(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ)				*/
BYTE *p0;	/* 省略前のﾊﾟｽ名(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ)					*/
INT32 flag;	/* ﾋﾞｯﾄ0:  1=ﾌｧｲﾙ名の部分のみを取り出す					*/
		/* ﾋﾞｯﾄ1:  1=半角の小文字を大文字化する  				*/
		/* ﾋﾞｯﾄ4:  1=省略開始位置を通常より1つ前にずらす			*/
		/* ﾋﾞｯﾄ5:  1=ﾊﾟｽ名/ﾌｧｲﾙ名でない一般文字列の省略				*/
		/*           （ﾋﾞｯﾄ0,4は必ず0を指定すること)				*/
INT32 xsize;	/* 表示領域の横方向のﾋﾟｸｾﾙ数(32000以上ならば省略の必要なしと見なす)	*/
BYTE *wid;	/* 文字幅ﾃｰﾌﾞﾙ[256] --- [0x20]～[0x80],[0xa0]～[0xdf],[252]だけが有効	*/
		/*                      [252]が全角1文字の横幅				*/
		/* 通常はgetfontwid()で設定した文字幅ﾃｰﾌﾞﾙを指定する			*/
{
	INT32 i,j,k,l1,x,x1,x2,x3,xs,xn,xx[PATHSIZE];
	BYTE *p,*q,*ps,*qq,*pp[PATHSIZE];
	BYTE cc,tttt[PATHSIZE];

	if( flag&0x01 ) {	/* ﾌｧｲﾙ名部分のみを取り出す */
		for( p=q=p0 ; ; ) {
			if( ctypesjis[*p]&CASCII ) {
				if( *p == '\\' )
					q = p+1;
				p++;
			}
			else if( ctypesjis[*p]&CKANJI1 )
				p += 2;
			else if( ctypesjis[*p]&CUNIMARK ) {
				if( *p == UCS2MARK )
					p += 3;
				else
					p += 5;
			}
			else	/* ﾇﾙｺｰﾄﾞ/ﾀﾌﾞｺｰﾄﾞ/制御ｺｰﾄﾞ */
				break;
		}
	}
	else {
		q = p0;
	}
	if( xsize >= 32000 ) {	/* 横幅が十分大きい --- 省略の必要がない場合 */
		for( p = p1 ; ; ) {
			if( ctypesjis[*q]&CASCII )
				*p++ = *q++;
			else if( ctypesjis[*q]&CKANJI1 ) {
				*p++ = *q++;
				*p++ = *q++;
			}
			else if( ctypesjis[*q]&CUNIMARK ) {
				if( *q == UCS2MARK ) {
					*p++ = *q++;
					*p++ = *q++;
					*p++ = *q++;
				}
				else {
					*p++ = *q++;
					*p++ = *q++;
					*p++ = *q++;
					*p++ = *q++;
					*p++ = *q++;
				}
			}
			else	/* ﾇﾙｺｰﾄﾞ/ﾀﾌﾞｺｰﾄﾞ/制御ｺｰﾄﾞ */
				break;
		}
		*p = '\0';
		xabbre = 0;
		return(q);
	}
	x1 = (INT32)(*(wid+46)*3);	/* ... の横幅 */
	l1 = 3;				/* ... の文字数 */
	x2 = (INT32)(*(wid+252));	/* 漢字1文字の横幅 */
	x3 = x1+x2+x2;			/* 一般文字列の長さをﾁｪｯｸする際の余裕分 */
	for( p=p1,x=i=0 ; ; ) {		/* ﾊﾟｽ名の表示幅を計算する */
		if( ctypesjis[*q]&CASCII ) {
			if( *q == '\\' ) {
				pp[i] = p;
				xx[i++] = x;
				x += (INT32)(*(wid+(INT32)*q));
				*p++ = *q++;
			}
			else if( *q >= 'a' && *q <= 'z' ) {
				cc = *q++;
				if( flag&0x02 )
					cc -= 0x20;
				x += (INT32)(*(wid+(INT32)cc));
				*p++ = cc;
			}
			else {
				x += (INT32)(*(wid+(INT32)*q));
				*p++ = *q++;
			}
		}
		else if( ctypesjis[*q]&CKANJI1 ) {
			x += x2;
			*p++ = *q++;
			*p++ = *q++;
		}
		else if( ctypesjis[*q]&CUNIMARK ) {
			k = getucscol(q);
			if( k == 2 )	/* 全角UCS-2、UCS-4 */
				x += x2;
			else		/* 半角UCS-2 */
				x += (INT32)(*(wid+0x0043));	/* C の横幅と同じと見なす */
			if( *q == UCS2MARK ) {
				*p++ = *q++;
				*p++ = *q++;
				*p++ = *q++;
			}
			else {
				*p++ = *q++;
				*p++ = *q++;
				*p++ = *q++;
				*p++ = *q++;
				*p++ = *q++;
			}
		}
		else		/* ﾇﾙｺｰﾄﾞ/ﾀﾌﾞｺｰﾄﾞ/制御ｺｰﾄﾞ */
			break;
		if( flag&0x20 ) {	/* 省略対象は一般文字列(通常は検索/置換文字列) */
			if( x > (xsize+x3) )
				break;
		}
	}
	*p = '\0';
	if( x <= xsize ) {
		xabbre = x;
		return(q);	/* 省略の必要なし */
	}
	if( flag&0x20 ) {	/* 省略対象は一般文字列(通常は検索/置換文字列) */
		i = 0;
		goto notfnam;
	}
	/* ﾌｫﾙﾀﾞ名部分の省略 */
	if( i > 2 && (pp[0]+1) == pp[1] ) {	/* ﾈｯﾄﾜｰｸﾊﾟｽ名の場合 */
		j = 3;
		if( i < 5 )
			j = 2;
	}
	else
		j = 1;
	if( flag&0x10 )
		j--;
	if( (j+1) < i ) {	/* 省略すべきﾌｫﾙﾀﾞ名部分がある */
		xs = xx[j]+(INT32)(*(wid+0x5c));
		ps = pp[j]+1;
		for( j++ ; j < i ; j++ ) {
			xn = x+x1-xx[j]+xs;
			if( xn <= xsize || (j+1) == i ) {
				for( p=tttt,qq=pp[j] ; *qq ; *p++ = *qq++ ) ;
				*p = '\0';
				p = ps;
				*p++ = '.';	/* ... */
				*p++ = '.';
				*p++ = '.';
				for( qq = tttt ; *qq ; *p++ = *qq++ ) ;
				*p = '\0';
				if( xn <= xsize ) {
					xabbre = xn;
					return(q);
				}
				else {
					ps += (l1+1);		/* ...\ */
					xs += (x1+(*(wid+0x5c)));
					x = xn;
					break;
				}
			}
		}
	}
	else {		/* ﾌｧｲﾙ名部分だけの省略 */
		if( i > 0 ) {
			ps = pp[i-1]+1;
			xs = xx[i-1]+(INT32)(*(wid+0x5c));
		}
		else {
			notfnam:
			ps = p1;
			xs = 0;
		}
	}
	/* ﾌｧｲﾙ名部分の省略 */
	for( p = ps ; ; ) {
		if( ctypesjis[*p]&CASCII ) {
			j = 1;
			k = (INT32)(*(wid+(INT32)*p));
		}
		else if( ctypesjis[*p]&CKANJI1 ) {
			j = 2;
			k = x2;
		}
		else if( ctypesjis[*p]&CUNIMARK ) {
			k = getucscol(p);
			if( k == 2 )
				k = x2;
			else
				k = (INT32)(*(wid+0x0043));	/* C の横幅と同じと見なす */
			if( *p == UCS2MARK )
				j = 3;
			else
				j = 5;
		}
		else		/* ﾇﾙｺｰﾄﾞ/ﾀﾌﾞｺｰﾄﾞ/制御ｺｰﾄﾞ */
			break;
		if( (xs+k+x1) > xsize ) {
			*p++ = '.';	/* ... */
			*p++ = '.';
			*p++ = '.';
			*p = '\0';
			xabbre = xs+x1;
			return(q);
		}
		p += j;
		xs += k;
	}
	xabbre = xs;
	return(q);
}

/* 指定ﾌｫﾝﾄで指定文字列を表示した時の表示横幅(ﾋﾟｸｾﾙ)を計算する		*/
INT32 getdispwidth(p,wid)
BYTE *p;	/* 表示幅を計算する文字列(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ)		*/
BYTE *wid;	/* 文字幅ﾃｰﾌﾞﾙ						*/
		/* 通常はgetfontwid()で設定した文字幅ﾃｰﾌﾞﾙを指定する	*/
{
	INT32 n;

	for( n = 0 ; ; ) {
		if( ctypesjis[*p]&CASCII ) {
			n += (INT32)(*(wid+(INT32)*p));
			p++;
		}
		else if( ctypesjis[*p]&CKANJI1 ) {
			n += (INT32)(*(wid+252));
			p += 2;
		}
		else if( ctypesjis[*p]&CUNIMARK ) {
			if( getucscol(p) == 2 )
				n += (INT32)(*(wid+252));
			else
				n += (INT32)(*(wid+'C'));
			if( *p == UCS2MARK )
				p += 3;
			else
				p += 5;
		}
		else
			break;
	}
	return(n);
}

INT32 hank2zenk(pz,ph,max)	/* 半角ｶﾀｶﾅを全角ｶﾀｶﾅに変換する */
BYTE *pz;	/* 全角ｶﾀｶﾅに変換後の文字列(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
BYTE *ph;	/* 半角ｶﾀｶﾅを含んだ文字列(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
INT32 max;	/* 変換後文字列の最大ﾊﾞｲﾄ数(終端のﾇﾙｺｰﾄﾞは含まない) */
{
	INT32 i;

	for( i = 0 ; *ph && i < max ; ) {
		if( ctypesjis[*ph]&CASCII ) {
			if( *ph >= 0xa0 && *ph <= 0xdd ) {	/* 半角ｶﾅ */
				if( *(ph+1) == 0xde ) {		/* ﾞ */
					if( *ph == 0xb3 ) {	/* ｳﾞ */
						*pz++ = 0x83;
						*pz++ = 0x94;
						i += 2;
						ph += 2;
						continue;
					}
					else if( *ph >= 0xb6 && *ph <= 0xc1 ) {/* ｶｷｸｹｺ ｻｼｽｾｿ ﾀﾁ */
						*pz++ = 0x83;
						*pz++ = 0x4b+((*ph-0xb6)*2);
						i += 2;
						ph += 2;
						continue;
					}
					else if( *ph >= 0xc2 && *ph <= 0xc4 ) {/* ﾂﾃﾄ */
						*pz++ = 0x83;
						*pz++ = 0x64+((*ph-0xc2)*2);
						i += 2;
						ph += 2;
						continue;
					}
					else if( *ph >= 0xca && *ph <= 0xce ) {/* ﾊﾋﾌﾍﾎ */
						*pz++ = 0x83;
						*pz++ = 0x6f+((*ph-0xca)*3);
						i += 2;
						ph += 2;
						continue;
					}
				}
				else if( *(ph+1) == 0xdf ) {	/* ﾟ */
					if( *ph >= 0xca && *ph <= 0xce ) {/* ﾊﾋﾌﾍﾎ  */
						*pz++ = 0x83;
						*pz++ = 0x70+((*ph-0xca)*3);
						i += 2;
						ph += 2;
						continue;
					}
				}
				if( *ph < 0xa5 ) {
					*pz++ = 0x81;
					if( *ph == 0xa0 )	/* ｽﾍﾟｰｽ */
						*pz++ = 0x40;
					else if( *ph == 0xa1 )	/* ｡ */
						*pz++ = 0x42;
					else if( *ph == 0xa2 )	/* ｢ */
						*pz++ = 0x75;
					else if( *ph == 0xa3 )	/* ｣ */
						*pz++ = 0x76;
					else if( *ph == 0xa4 )	/* ､ */
						*pz++ = 0x41;
					else if( *ph == 0xa5 )	/* ･ */
						*pz++ = 0x45;
					i += 2;
				}
				else if( *ph == 0xb0 ) {	/* ｰ */
					*pz++ = 0x81;
					*pz++ = 0x5b;
					i += 2;
				}
				else {
					*pz++ = 0x83;
					*pz++ = h2zkana[*ph-0xa6];
					i += 2;
				}
				ph++;
			}
			else {		/* その他の半角文字 */
				*pz++ = *ph++;
				i++;
			}
		}
		else if( ctypesjis[*ph]&CKANJI1 ) {
			*pz++ = *ph++;
			*pz++ = *ph++;
			i += 2;
		}
		else if( ctypesjis[*ph]&CUNIMARK ) {
			if( *ph == UCS2MARK ) {
				*pz++ = *ph++;
				*pz++ = *ph++;
				*pz++ = *ph++;
				i += 3;
			}
			else {
				*pz++ = *ph++;
				*pz++ = *ph++;
				*pz++ = *ph++;
				*pz++ = *ph++;
				*pz++ = *ph++;
				i += 5;
			}
		}
		else		/* 不当なｺｰﾄﾞ */
			break;
	}
	*pz = '\0';	/* 終端にﾇﾙｺｰﾄﾞを付加 */
	return(i);
}

INT32 urlhexstr(q,c,flag)	/* 1ﾊﾞｲﾄのｺｰﾄﾞを半角 % に続く16進文字列(2桁)に変換する */
BYTE *q;	/* 変換後の16進文字列(3桁)を返すﾊﾞｯﾌｧ	*/
DWORD c;	/* 変換する1ﾊﾞｲﾄのｺｰﾄﾞ(最下位8ﾋﾞｯﾄのみ有効)		*/
INT32 flag;	/* ﾋﾞｯﾄ0:  0=16進文字列は大文字  1=16進文字列は小文字	*/
{
	*q = '%';
	*(q+1) = hexsss[(c>>4)&0x000f];
	*(q+2) = hexsss[c&0x000f];
	if( flag&0x0001 ) {	/* 16進数は小文字 */
		if( *(q+1) >= 'A' && *(q+1) <= 'Z' )
			*(q+1) += 0x20;
		if( *(q+2) >= 'A' && *(q+2) <= 'Z' )
			*(q+2) += 0x20;
	}
	return(3);	/* 変換後の16進文字列のﾊﾞｲﾄ数を返す */
}

/* URLｴﾝｺｰﾃﾞｨﾝｸﾞ用の文字列変換処理(変換後の文字列のﾊﾞｲﾄ数を返す) */
INT32 str2euc16(buff,str,max,flag)
BYTE *buff;	/* 変換後の文字列 */
BYTE *str;	/* 変換前の文字列 */
INT32 max;	/* 変換後の最大ﾊﾞｲﾄ数(最後のﾇﾙｺｰﾄﾞを含まないﾊﾞｲﾄ数 --- 最大500ﾊﾞｲﾄ)	*/
INT32 flag;	/* ﾋﾞｯﾄ0:  0=16進文字列は大文字  1=16進文字列は小文字			*/
		/* ﾋﾞｯﾄ4:  0=半角ｶﾅはそのまま  1=半角ｶﾅは全角ｶﾅに変換			*/
		/* ﾋﾞｯﾄ8:  0=半角ｽﾍﾟｰｽの連続はそのまま  1=半角ｽﾍﾟｰｽの連続は半角+に変換	*/
		/* ﾋﾞｯﾄ12: 0=EUCの16進文字列に変換  1=UTF-8の16進文字列に変換		*/
{
	BYTE *p,*q,buff1[512];
	WCHAR uc[4];
	BYTE c1,c2,cc[8];

	if( flag&0x0010 ) {	/* 半角ｶﾅを全角ｶﾅに変換 */
		if( max > 510 )
			max = 510;
		hank2zenk(buff1,str,max);
		p = buff1;
	}
	else
		p = str;
	for( q = buff ; *p ; ) {
		if( ctypesjis[*p]&CASCII ) {
			if( *p == ' ' ) {
				if( flag&0x0100 ) {	/* 半角ｽﾍﾟｰｽの連続は半角 + に変換 */
					for( ; *p == ' ' ; p++ ) ;
					*q++ = '+';
				}
				else {
					*q++ = ' ';
					p++;
				}
			}
			else if( flag&0x1000 ) {/* UTF-8の16進文字列に変換 */
				if( *p < 0x80 )		/* ANSI文字 */
					*q++ = *p++;
				else if( *p >= 0xa0 && *p <= 0xdf ) {	/* 半角ｶﾅ */
					miw2unicode(p,uc);
					p++;
					goto utf8encode2;
				}
				else if( *p == 0x80 ) {
					uc[0] = 0x0080;
					p++;
					goto utf8encode2;
				}
				else
					break;
			}
			else {			/* EUCの16進文字列に変換 */
				*q++ = *p++;
			}
		}
		else if( ctypesjis[*p]&CKANJI1 ) {
			if( flag&0x1000 ) {	/* UTF-8の16進文字列に変換 */
				cc[0] = *p++;
				cc[1] = *p++;
				utf8encode1:
				miw2unicode(cc,uc);
				utf8encode2:
				if( uc[0] <= 0x007f ) {		/* 7ﾋﾞｯﾄｺｰﾄﾞ */
					if( (q+3) > (buff+max) )
						break;
					q += urlhexstr(q,(BYTE)uc[0],flag);
				}
				else if( uc[0] <= 0x07ff ) {	/* 11(=5+6)ﾋﾞｯﾄｺｰﾄﾞ */
					if( (q+6) > (buff+max) )
						break;
					q += urlhexstr(q,0xc0|(BYTE)((uc[0]>>6)&0x001f),flag);
					q += urlhexstr(q,0x80|(BYTE)(uc[0]&0x003f),flag);
				}
				else {				/* 16(4+6+6)ﾋﾞｯﾄｺｰﾄﾞ */
					if( (q+9) > (buff+max) )
						break;
					q += urlhexstr(q,0xe0|(BYTE)(uc[0]>>12),flag);
					q += urlhexstr(q,0x80|(BYTE)((uc[0]>>6)&0x003f),flag);
					q += urlhexstr(q,0x80|(BYTE)(uc[0]&0x003f),flag);
				}
			}
			else {			/* EUCの16進文字列に変換 */
				if( (q+6) > (buff+max) )
					break;
				c1 = *p++;
				c2 = *p++;
				if( c1 >= 0xe0 )
					c1 -= 0x40;
				if( c2 < 0x80 ) {
					c1 += c1;
					c1 += 0x1f;
					c2 -= 0x1f;
				}
				else if( c2 < 0x9f ) {
					c1 += c1;
					c1 += 0x1f;
					c2 -= 0x20;
				}
				else {
					c1 += c1;
					c1 += 0x20;
					c2 -= 0x7e;
				}
				c1 += 0x80;
				c2 += 0x80;
				q += urlhexstr(q,c1,flag);
				q += urlhexstr(q,c2,flag);
			}
		}
		else if( ctypesjis[*p]&CUNIMARK ) {
			if( flag&0x1000 ) {	/* UTF-8の16進文字列に変換 */
				if( *p == UCS2MARK ) {	/* UCS-2 */
					cc[0] = *p++;
					cc[1] = *p++;
					cc[2] = *p++;
					goto utf8encode1;
				}
				else {			/* UCS-4 */
					cc[0] = *p++;
					cc[1] = *p++;
					cc[2] = *p++;
					cc[3] = *p++;
					cc[4] = *p++;
					miw2unicode(cc,uc);
					if( uc[1] >= UCS4SAROGATE1 && uc[1] <= UCS4SAROGATE2 && 
						uc[0] >= UCS4SAROGATE3 && uc[0] <= UCS4SAROGATE4 ) {
#ifdef UTF8UCS4
						if( (q+12) > (buff+max) )
							break;
						uc[1] -= UCS4SAROGATE0;	/* 11ﾋﾞｯﾄ数(0～0x07ff) */
						uc[0] -= UCS4SAROGATE3;	/* 10ﾋﾞｯﾄ数(0～0x03ff) */
						q += urlhexstr(q,0xf0|((uc[1]>>8)&0x0007),flag);
						q += urlhexstr(q,0x80|((uc[1]>>2)&0x003f),flag);
						q += urlhexstr(q,0x80|((uc[1]&0x0003)<<4)|((uc[0]>>6)&0x000f),flag);
						q += urlhexstr(q,0x80|(uc[0]&0x003f),flag);
#else
						if( (q+18) > (buff+max) )
							break;
						q += urlhexstr(q,0xe0|(BYTE)(uc[1]>>12),flag);
						q += urlhexstr(q,0x80|(BYTE)((uc[1]>>6)&0x003f),flag);
						q += urlhexstr(q,0x80|(BYTE)(uc[1]&0x003f),flag);
						q += urlhexstr(q,0xe0|(BYTE)(uc[0]>>12),flag);
						q += urlhexstr(q,0x80|(BYTE)((uc[0]>>6)&0x003f),flag);
						q += urlhexstr(q,0x80|(BYTE)(uc[0]&0x003f),flag);
#endif
					}
					else		/* UCS-4以外のUTF-32 */
						break;
				}
			}
			else {			/* EUCの16進文字列に変換 */
				break;
			}
		}
		if( (q+1) > (buff+max) )
			break;
	}
	*q = '\0';
	return((INT32)(q-buff));
}

INT32 urljump(fmt,str)
BYTE *fmt;	/* URLｴﾝｺｰﾃﾞｨﾝｸﾞ用の書式文字列(ｼﾌﾄJISﾌｫｰﾏｯﾄ)	*/
BYTE *str;	/* 展開用の検索文字列(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
{
	BYTE *p,*p0,*q,buff[512];

	for( p = fmt ; *p && *p != ' ' ; p++ ) ;
	if( *p == ' ' ) {
		for( ; *p == ' ' ; p++ ) ;
		if( *p )
			fmt = p;
	}
	for( p=p0=buff ; *fmt && p < (p0+500) ; ) {
		if( ctypesjis[*fmt]&CASCII ) {
			if( *fmt == '%' ) {
				fmt++;
				if( *fmt == 's' || *fmt == 'S' ) {	/* ｼﾌﾄJISｺｰﾄﾞに展開 */
					for( q = str ; *q ; ) {
						if( ctypesjis[*q]&CASCII ) {
							if( *q == ' ' ) {
								if( (p+1) > (p0+500) )
									break;
								for( ; *q == ' ' ; q++ ) ;
								*p++ = '+';
							}
							else {
								if( (p+1) > (p0+500) )
									break;
								*p++ = *q++;
							}
						}
						else if( ctypesjis[*q]&CKANJI1 ) {
							if( (p+2) > (p0+500) )
								break;
							*p++ = *q++;
							*p++ = *q++;
						}
						else		/* ｼﾌﾄJISｺｰﾄﾞに変換できない文字 */
							break;
					}
					fmt++;
				}
				else if( *fmt == 'e' || *fmt == 'E' ) {	/* EUCの16進文字列に展開 */
					p += str2euc16(p,str,(INT32)(p0+500-p),(*fmt=='e')?0x0111:0x0110);
					fmt++;
				}
				else if( *fmt == 'u' || *fmt == 'U' ) {	/* UTF-8の16進文字列に展開 */
					p += str2euc16(p,str,(INT32)(p0+500-p),(*fmt=='u')?0x1111:0x1110);
					fmt++;
				}
				else
					*p++ = '%';
			}
			else
				*p++ = *fmt++;
		}
		else if( ctypesjis[*fmt]&CKANJI1 ) {	/* 通常はあり得ないが */
			if( (p+2) > (p0+500) )
				break;
			*p++ = *fmt++;
			*p++ = *fmt++;
		}
		else
			break;
	}
	*p = '\0';
	if( p > p0 )
		return(!gourl(buff,0));
	else
		return(0);
}

/* ｶｰｿﾙ位置がURLやﾒｰﾙｱﾄﾞﾚｽであるかどうかﾁｪｯｸする			*/
/*   -2:URL/ﾒｰﾙｱﾄﾞﾚｽだが、ﾕｰｻﾞｰが段落/語を範囲選択(flag=1の時のみ)	*/
/*   -1:URL/ﾒｰﾙｱﾄﾞﾚｽだが、ﾕｰｻﾞｰがｷｬﾝｾﾙ(flag=1の時のみ)			*/
/*    0:URLでもﾒｰﾙｱﾄﾞﾚｽでもない						*/
/*    1:URLまたはﾌﾞﾗｳｻﾞを起動した					*/
/*    2:ﾒｰﾙｱﾄﾞﾚｽまたはﾒｰﾗｰを起動した					*/
INT32 chkurl(flag,cp,clp)
INT32 flag;	/* 0=ﾁｪｯｸのみ  1=ﾁｪｯｸと確認とｼﾞｬﾝﾌﾟ  2=ﾁｪｯｸとｼﾞｬﾝﾌﾟ */
BYTE *cp;	/* ｶｰｿﾙ位置(mp->ecursp) */
BYTE *clp;	/* ｶｰｿﾙ表示行位置(mp->ecurslp) */
{
	INT32 i,j;
	BYTE *p,*q,*p0,*p1,*q0,c1,c2,buff[1024],buff1[1024];

	for( p=cp,q=&buff[512],i=0 ; i < 500 ; ) {	/* ｶｰｿﾙ位置以降のURL文字列を取得 */
		if( ctypex[*p]&CASCII ) {
			if( urlchr1(p) ) {
				*q++ = *p++;
				i++;
			}
			else
				break;
		}
		else if( ctypex[*p]&(CKANJI1|CUNIMARK) )
			break;
		else if( *p == 0x09 )
			break;
		else if( *p == BINMARK )
			break;
		else if( *p == RECMARK ) {
			if( (*(p+1)&0x03) == LINE0C )
				p += INFOSIZE1;
#ifdef URLBREAK
			else
				break;
#else
			else if( mp->langflg != 4 )
				break;
			else if( (*(p+1)&0x03) == LINE3C )
				break;
			else if( *(p-1) != '/' && *(p+INFOSIZE1) != '/' )
				break;
			else if( urlchr1(p+INFOSIZE1) )
				p += INFOSIZE1;
			else
				break;
#endif
		}
		else		/* あり得ない */
			break;
	}
	*q = '\0';
	p0 = clp;
	j = 0;
	urlloop:
	p = p0;
	for( q = &buff[512] ; p < cp ; ) {
		for( ; p < cp ; ) {	/* URL/ﾒｰﾙｱﾄﾞﾚｽの先頭位置を探す */
			if( ctypex[*p]&CASCII ) {
				if( urlchr1(p) )
					break;
				else
					p++;
			}
			else if( ctypex[*p]&CKANJI1 )
				p += 2;
			else if( *p == 0x09 )
				p++;
			else if( ctypex[*p]&CUNIMARK ) {
				if( *p == UCS2MARK )
					p += 3;
				else
					p += 5;
			}
			else if( *p == BINMARK )
				p += 2;
			else if( *p == RECMARK )
				p += INFOSIZE1;
			else		/* あり得ない */
				p++;
		}
		p1 = p;
		for( q=buff1,i=0 ; i < 500 && p < cp ; ) {	/* URL/ﾒｰﾙｱﾄﾞﾚｽのｶｰｿﾙ以前の最終位置を探す */
			if( ctypex[*p]&CASCII ) {
				if( urlchr1(p) ) {
					*q++ = *p++;
					i++;
				}
				else
					break;
			}
			else if( ctypex[*p]&(CKANJI1|CUNIMARK) )
				break;
			else if( *p == 0x09 )
				break;
			else if( *p == BINMARK )
				break;
			else if( *p == RECMARK )
				p += INFOSIZE1;
			else		/* あり得ない */
				p++;
		}
		if( p >= cp ) {
			if( i > 0 )
				movetxtb(&buff[512],q,i);
			q = &buff[512]-i;
			break;
		}
	}
	for( ; *q ; q++ ) {
		if( *q=='h' && *(q+1)=='t' && *(q+2)=='t' && *(q+3)=='p' && 
			*(q+4)==':' && *(q+5)=='/' && *(q+6)=='/' ) {
			p = q+7;
			goto urlquery;
		}
		else if( *q=='h' && *(q+1)=='t' && *(q+2)=='t' && *(q+3)=='p' && *(q+4)=='s' && 
			*(q+5)==':' && *(q+6)=='/' && *(q+7)=='/' ) {
			p = q+8;
			goto urlquery;
		}
		else if( *q=='f' && *(q+1)=='i' && *(q+2)=='l' && *(q+3)=='e' && 
			*(q+4)==':' && *(q+5)=='/' && *(q+6)=='/' ) {
			p = q+7;
			urlquery:
			for( ; *p ; p++ ) ;
			if( &buff[512] < q || p <= &buff[512] )		/* &buff[512] = 現在のｶｰｿﾙ位置 */
				return(0);
			/* ｶｰｿﾙ位置がURL */
			if( flag == 0 )
				return(1);
			else if( flag == 1 ) {
				if( exsysmode&EXSYS_NOURLMS )
					i = 1;
				else {
					*(q-1) = 0x00;
					i = dialogboxparamO(hinst,IDD_URLJUMP,hfwnd,UrlDlg,(LPARAM)(q-1));
				}
			}
			else {
				i = 1;
			}
			if( i == 1 ) {		/* はい */
				gourl(q,0);
				return(1);
			}
			else if( i == 2 )	/* 段落/語を範囲選択 */
				return(-2);
			else			/* ｷｬﾝｾﾙ */
				return(-1);
		}
		else if( p1 == p0 && (*(p0-INFOSIZE)&0x03) == LINE0C && (p0+500) > cp && p0 > mp->ebuffp && j < 4 ) {
			for( p0 -= INFOSIZE1 ; *(p0-INFOSIZE1) != RECMARK ; p0-- ) ;
			j++;
			goto urlloop;
		}
	}
	/* ﾒｰﾙｱﾄﾞﾚｽのﾁｪｯｸ */
	for( p=cp,q=&buff[128],i=0 ; i < 124 ; i++ ) {
		if( (ctypex[*p]&CMAIL) || *p == '@' )
			*q++ = *p++;
		else if( *p == RECMARK && (*(p+1)&0x03) == LINE0C ) {
			p += INFOSIZE1;
			continue;
		}
		else
			break;
	}
	*q = '\0';
	for( p=cp,q=&buff[128],i=0 ; p > mp->ebuffp && i < 124 ; ) {
		p--;
		if( *(p-INFOSIZE) == RECMARK ) {
			if( *(p-INFOSIZE+1)&0x03 )
				break;
			p -= INFOSIZE;
			continue;
		}
		if( (ctypex[*p]&CMAIL) || *p == '@' ) {
			if( p > mp->ebuffp && (ctypex[*(p-1)]&CKANJI1) ) {
				if( chkzen2(clp,p) == 0 ) {	/* 位置 p は1ﾊﾞｲﾄ文字 */
					*(--q) = *p;
					i++;
				}
				break;
			}
			*(--q) = *p;
			i++;
		}
		else
			break;
	}
	/* 取り出した文字列がﾒｰﾙｱﾄﾞﾚｽとして正当かどうかをﾁｪｯｸする */
	for( p=q,i=0 ; *q ; q++ ) {
		if( *q == '@' && q > p ) {	/* 文字列の途中に半角「@」がある */
			if( &buff[128] < p )	/* &buff[128]=ｶｰｿﾙ位置  p=ﾒｰﾙｱﾄﾞﾚｽ先頭位置 */
				return(0);
			c1 = *(q-1);	/* @ 直前の1文字 */
			q0 = q++;
			c2 = *q;	/* @ 直後の1文字 */
			for( j = 0 ; *q && *q != '@' ; q++ ) {
				if( *q == '.' ) {
					if( *(q-1) == '@' || *(q+1) == '@' || *(q+1) == '\0' )
						return(0);
					j++;
				}
			}
			*q = '\0';
			if( q <= &buff[128] ) {	/* &buff[128]=ｶｰｿﾙ位置  q=ﾒｰﾙｱﾄﾞﾚｽ最終位置 */
				q = q0;
				p = q+1;
				continue;
			}
			if( j == 0 )		/* 半角「@」以降に半角「.」がない */
				return(0);
			if( c1 == '!' || c1 == '+' || c1 == '-' || c1 == '.' )	/* @ 直前の1文字は ! + - . であってはならない */
				return(0);
			if( c2 == '!' || c2 == '+' || c2 == '-' || c2 == '.' )	/* @ 直後の1文字は ! + - . であってはならない */
				return(0);
			/* ｶｰｿﾙ位置がﾒｰﾙｱﾄﾞﾚｽ */
			if( flag == 0 )
				return(2);
			else if( flag == 1 ) {
				if( exsysmode&EXSYS_NOURLMS )
					i = 1;
				else {
					*(p-1) = 0x01;		/* ﾒｰﾗｰ起動の確認 */
					i = dialogboxparamO(hinst,IDD_URLJUMP,hfwnd,UrlDlg,(LPARAM)(p-1));
				}
			}
			else {
				i = 1;
			}
			if( i == 1 ) {		/* はい */
				sendmail(p/*宛先名*/,"","","","","","");
				return(2);
			}
			else if( i == 2 )	/* 段落/語を範囲選択 */
				return(-2);
			else			/* ｷｬﾝｾﾙ */
				return(-1);
		}
		else if( *q == '@' ) {	/* @ の前に @ があってはならない */
			p = q+1;
		}
	}
	return(0);
}

INT32 regenvstr(q0,p0,p1)
BYTE *q0;
BYTE *p0;
BYTE *p1;
{
	BYTE *p,*q,*r,env[128],envvari[256];

	for( p=p0,q=q0 ; *p ; ) {
		if( *p == '%' ) {
			p++;
			if( *p == '1' ) {
				q += fstrcpy(q,p1);
				p++;
			}
			else if( *p >= '0' && *p <= '9' ) {
				p++;
			}
			else {
				for( r = env ; *p != '%' && *p ; )
					*r++ = *p++;
				*r = '\0';
				if( *p == '%' ) {
					p++;
					if( r > env ) {
						if( GetEnvironmentVariable(env,envvari,256) > 0 ) {
							for( r = envvari ; *r ; )
								*q++ = *r++;
						}
					}
				}
			}
		}
		else
			*q++ = *p++;
	}
	*q = '\0';
	return((INT32)(q-q0));
}

/* 対応するｱﾌﾟﾘｹｰｼｮﾝに ﾌｧｲﾙ/URL を送る			*/
/*  0:送った						*/
/*  1:拡張子が見つからない				*/
/*  2:拡張子がﾚｼﾞｽﾄﾘに定義されていない			*/
/*  3:拡張子に対応するｺﾏﾝﾄﾞが見つからない		*/
/*  4:拡張子に対応するｺﾏﾝﾄﾞはMIFES自身			*/
/*  5:拡張子に対応するｺﾏﾝﾄﾞが実行できなかった		*/
INT32 gourl(url,flag)
BYTE *url;	/* ｱﾌﾟﾘｹｰｼｮﾝに送るﾊﾟｽ名またはURL */
INT32 flag;	/* 送るｱﾌﾟﾘｹｰｼｮﾝの指定 */
		/* 0:URL(*url)へｼﾞｬﾝﾌﾟ */
		/* 1:拡張子.bmp に関連付けされたｱﾌﾟﾘｹｰｼｮﾝ(editｺﾏﾝﾄﾞ)--> ﾋﾞｯﾄﾏｯﾌﾟﾌｧｲﾙの編集 */
		/* 2:拡張子.txt に関連付けされたｱﾌﾟﾘｹｰｼｮﾝ(openｺﾏﾝﾄﾞ)--> 未使用 */
		/* 9:ﾊﾟｽ名 *url の拡張子に関連付けされたｱﾌﾟﾘｹｰｼｮﾝ(openｺﾏﾝﾄﾞ)--> ﾌｧｲﾙのｵｰﾌﾟﾝ */
		/* 10:ﾒｰﾗｰ --> ﾒｰﾙの編集 */
{
	INT32 i,j,ii,jj;
	DWORD err,dwtype,dwsize;
	HKEY hk;
	SHELLEXECUTEINFO exeinfo;
	STARTUPINFO start;
	PROCESS_INFORMATION info;
	BYTE cmd[1024],path[PATHSIZE],argstr[PATHSIZE],optionstr[520],*p,*q,*r;

	if( flag == 0 ) {	/* URLへのｼﾞｬﾝﾌﾟ */
		if( (INT32)ShellExecute(NULL,"open",url,NULL,NULL,SW_SHOWNORMAL) > 32 )
			return(0);	/* 成功 */
	}
	if( flag < 10 ) {	/* 拡張子によりｱﾌﾟﾘｹｰｼｮﾝを決定する */
		if( flag == 0 )
			fstrcpy(cmd,".htm");
		else if( flag == 1 )
			fstrcpy(cmd,".bmp");
		else if( flag == 2 )
			fstrcpy(cmd,".txt");
		else {
			for( p=url,q=NULL ; *p ; p++ ) {
				if( *p == '.' )
					q = p;
			}
			if( q == NULL )
				return(1);
			fstrcpy(cmd,q);
		}
		err = RegOpenKeyEx(HKEY_CLASSES_ROOT,cmd,0,KEY_READ,&hk);
		if( err != ERROR_SUCCESS )
			return(2);
		dwtype = REG_SZ;
		dwsize = PATHSIZE;
		err = RegQueryValueEx(hk,NULL,NULL,&dwtype,path,&dwsize);
		RegCloseKey(hk);
		if( err != ERROR_SUCCESS )
			return(2);
		for( r = path ; *r ; r++ ) ;
		if( flag == 1 )	/* .bmp */
			fstrcpy(r,"\\shell\\edit\\command");
		else
			fstrcpy(r,"\\shell\\open\\command");
	}
	else {		/* ﾒｰﾗｰに送る */
		fstrcpy(path,"mailto\\shell\\open\\command");
	}
	err = RegOpenKeyEx(HKEY_CLASSES_ROOT,path,0,KEY_READ,&hk);
	if( err != ERROR_SUCCESS ) {
		if( flag == 1 ) {	/* .bmp */
			fstrcpy(r,"\\shell\\open\\command");	/* openｺﾏﾝﾄﾞで再検索 */
			err = RegOpenKeyEx(HKEY_CLASSES_ROOT,path,0,KEY_READ,&hk);
			if( err != ERROR_SUCCESS )
				return(3);
		}
		else
			return(3);
	}
	dwtype = REG_SZ;
	dwsize = PATHSIZE;
	err = RegQueryValueEx(hk,NULL,NULL,&dwtype,path,&dwsize);
	RegCloseKey(hk);
	if( err != ERROR_SUCCESS )
		return(3);
	for( q=url,jj=0 ; *q ; q++ ) {
		if( *q == ' ' )
			jj++;		/* URL/ﾊﾟｽ名中の半角ｽﾍﾟｰｽを含む */
	}
	if( flag < 10 ) {	/* 拡張子によりｱﾌﾟﾘｹｰｼｮﾝを決定する */
		/* ﾀﾞﾌﾞﾙｸｵｰﾂとｵﾌﾟｼｮﾝを外す */
		if( path[0] == '"' ) {
			for( p=&path[1],q=path ; *p ; ) {
				if( *p == '"' ) {
					p++;
					if( *p == '"' )
						*q++ = *p++;
					else
						break;
				}
				else
					*q++ = *p++;
			}
			*q = '\0';
		}
		else {
			for( p = path ; *p && *p != ' ' ; p++ ) ;
			if( *p )
				*p++ = '\0';
		}
		ii = 0;
		for( ; *p == ' ' ; p++ ) ;
		for( q = optionstr ; *p ; ) {
			if( *p == '%' && *(p+1) == '1' ) {
				if( jj == 0 || *(p+2) == '\0' )
					q += fstrcpy(q,url);
				else {
					*q++ = '"';
					q += fstrcpy(q,url);
					*q++ = '"';
				}
				p += 2;
				ii++;
			}
			else
				*q++ = *p++;
		}
		*q = '\0';
		i = regenvstr(argstr,path,"");	/* 環境変数 %NAME% の展開 */
		if( i >= 7 && fstrcmpii(&argstr[i-7],"MIW.EXE") == 0 )	/* ｱﾌﾟﾘｹｰｼｮﾝはMIFES */
			return(4);	/* 既にｱﾌﾟﾘｹｰｼｮﾝに送っていると見なす */
		/* 子ﾌﾟﾛｾｽｺﾏﾝﾄﾞの組み立て */
		if( flag == 9 ) {	/* 拡張子に関連付けされたｱﾌﾟﾘｹｰｼｮﾝでﾌｧｲﾙをopen */
			p = cmd;
			*p++ = '"';
			p += fstrcpy(p,url);
			*p++ = '"';
			*p = '\0';
			exeinfo.cbSize = sizeof(SHELLEXECUTEINFO);
			exeinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
			exeinfo.hwnd  = hfwnd;
			exeinfo.lpVerb = "open";
			exeinfo.lpFile = cmd;
			/* exeinfo.lpVerb したいﾌｧｲﾙ名を exeinfo.lpFile に指定する */
			/* exeinfo.lpFile に実行ﾊﾟｽ名を指定すると、そのｱﾌﾟﾘｹｰｼｮﾝを実行する */
			exeinfo.lpParameters = NULL;
			/* exeinfo.lpFile に実行ﾊﾟｽ名を指定した場合に、*/
			/* そのｺﾏﾝﾄﾞﾗｲﾝのﾊﾟﾗﾒｰﾀを exeinfo.lpParameters に指定する */
			exeinfo.lpDirectory = NULL;
			exeinfo.nShow = SW_SHOWNORMAL;
			exeinfo.lpIDList = NULL;
			exeinfo.lpClass = NULL;
			exeinfo.hkeyClass = NULL;
			exeinfo.dwHotKey = 0;
			exeinfo.hIcon  = NULL;
			exeinfo.hProcess = NULL;
			if( ShellExecuteEx(&exeinfo) )
				return(0);
			return(5);
		}
		p = cmd;
		for( q=argstr,j=0 ; *q ; q++ ) {
			if( *q == ' ' )
				j++;
		}
		if( j == 0 )
			p += fstrcpy(p,argstr);
		else {
			*p++ = '"';
			p += fstrcpy(p,argstr);
			*p++ = '"';
		}
		if( optionstr[0] ) {
			*p++ = ' ';
			p += fstrcpy(p,optionstr);
		}
		if( ii == 0 ) {		/* ﾚｼﾞｽﾄﾘ定義中に %1 がない場合 */
			*p++ = ' ';
			if( jj == 0 )
				p += fstrcpy(p,url);
			else {
				*p++ = '"';
				p += fstrcpy(p,url);
				*p++ = '"';
			}
		}
		*p = '\0';
	}
	else {		/* ﾒｰﾗｰに送る */
		i = fstrcpy(argstr,"mailto:");
		fstrcpy(&argstr[i],url);
		regenvstr(cmd,path,argstr);
	}
	start.cb = sizeof(STARTUPINFO);
	start.lpReserved = NULL;
	start.lpDesktop = NULL;
	start.lpTitle = NULL;
	start.dwX = 0;
	start.dwY = 0;
	start.dwXSize = 0;
	start.dwYSize = 0;
	start.dwXCountChars = 0;
	start.dwYCountChars = 0;
	start.dwFillAttribute = 0;
	start.wShowWindow = 0;
	start.cbReserved2 = 0;
	start.lpReserved2 = NULL;
	start.dwFlags = 0;
	start.hStdInput = NULL;
	start.hStdOutput = NULL;
	start.hStdError = NULL;
	if( !createprocessM(
		cmd,		/* ｺﾏﾝﾄﾞﾗｲﾝ文字列(実行ﾌｧｲﾙ名を含んでもよい) */
		NULL,		/* ﾌﾟﾛｾｽのｾｷｭﾘﾃｨ属性(SECURITY_ATTRIBUTES) */
		NULL,		/* ｽﾚｯﾄﾞのｾｷｭﾘﾃｨ属性(SECURITY_ATTRIBUTES) */
		FALSE,		/* ﾌｧｲﾙﾊﾝﾄﾞﾙの子ﾌﾟﾛｾｽへの相続 */
		NORMAL_PRIORITY_CLASS,	/* 各種ﾌﾗｸﾞ */
		NULL,		/* 子ﾌﾟﾛｾｽの環境変数 */
		NULL,		/* 子ﾌﾟﾛｾｽの起動時のｶﾚﾝﾄﾃﾞｨﾚｸﾄﾘ */
		&start,		/* 子ﾌﾟﾛｾｽの初期ｳｨﾝﾄﾞｳ表示状態 */
		&info,		/* 子ﾌﾟﾛｾｽのﾌﾟﾛｾｽﾊﾝﾄﾞﾙなどが返される */
		NULL)		/* 子ﾌﾟﾛｾｽ起動完了待機用イベントハンドル(未使用) */
		) {		/* 子ﾌﾟﾛｾｽの実行に失敗した場合 */
		return(5);
	}
	return(0);	/* ｱﾌﾟﾘｹｰｼｮﾝに送った */
}

INT32 shgetline(q0,nmax)		/* ｶｰｿﾙ行の内容を指定ﾊﾞｯﾌｧに取り出す */
BYTE *q0;
INT32 nmax;
{
	INT32 n;
	BYTE *p,*q;

	p = mp->ecurslp;
	if( p > mp->ebuffp && *(p-INFOSIZE1) == RECMARK && (*(p-INFOSIZE)&0x03) == LINE0C ) {
		for( p -= INFOSIZE1 ; *(p-INFOSIZE1) != RECMARK ; p-- ) ;
		if( p > mp->ebuffp && *(p-INFOSIZE1) == RECMARK && (*(p-INFOSIZE)&0x03) == LINE0C ) {
			for( p -= INFOSIZE1 ; *(p-INFOSIZE1) != RECMARK ; p-- ) ;
		}
	}
	for( q=q0,n=nmax-1 ; n > 0 ; ) {
		if( *p == '>' ) {
			if( *(p+1) == '>' && 
				( ( *q0 == '\\' && *(q0+1) == '\\' ) || 
				( *(q0+1) == ':' && *(q0+2) == '\\' ) ) ) {	/* ﾌﾟﾛﾝﾌﾟﾄ行 */
				q = q0;
				n = nmax-1;
				p += 2;
			}
			else
				*q++ = *p++;
		}
		else if( ctypex[*p]&CASCII )
			*q++ = *p++;
		else if( *p == 0x09 )
			*q++ = *p++;
		else if( ctypex[*p]&CKANJI1 ) {
			*q++ = *p++;
			*q++ = *p++;
		}
		else if( ctypex[*p]&CUNIMARK ) {
			if( *p == UCS2MARK )
				p += 3;
			else
				p += 5;
		}
		else if( *p == RECMARK ) {
			if( *(p+1)&0x03 )
				break;
			p += INFOSIZE1;
		}
		else if( *p == BINMARK ) {
			p += 2;
		}
		else {		/* あり得ない */
			p++;
		}
	}
	*q = '\0';
	return((INT32)(q-q0));
}

INT32 shescret1()	/* ｼｪﾙｴｽｹｰﾌﾟ･ｳｨﾝﾄﾞｳにおける指定子ﾌﾟﾛｾｽの実行 */
{
	INT32 i,err;
	BYTE cmd[MAXCMDS];

	if( ppmac->dosdir[0] ) {
		SetErrorMode(SEM_FAILCRITICALERRORS);
		err = setcurrentdirectoryM(ppmac->dosdir);
		SetErrorMode(0);
	}
	i = getcurrentdirectoryM(cmd);
	cmd[i++] = ' ';
	cmd[i++] = '>';
	cmd[i++] = '>';
	insstr(0x12,i,cmd);
	postdo();
	for( i = 0 ; ppmac->dosexe[i] ; i++ ) ;
	insstr(0x12,i,ppmac->dosexe);
	postdo();
	i = shescret();
	if( i == 0 )
		return(0);
	cmd[0] = 0x0d;
	cmd[1] = 0x0a;
	insstr(0x12,2,cmd);
	postdo();
	return(i);
}

INT32 shescret()		/* ｼｪﾙｴｽｹｰﾌﾟ･ｳｨﾝﾄﾞｳにおける改行時の処理 */
{
	INT32 i,j,k,m,err;
	BYTE cmd[MAXCMDS],path[PATHSIZE],envstr[2048],*envss,*p,*p1,*p2,*p3,*p4;
	WIN32_FIND_DATA finddata;
	STARTUPINFO start;
	SECURITY_ATTRIBUTES securi,securi1,securi2;
	PROCESS_INFORMATION info;
	DWORD stat,flag;
	HANDLE readpipe1,writepipe1,readpipe2,writepipe2;

	if( mp->hprocess ) {	/* 前のﾌﾟﾛｾｽが終了していない */
		if( !GetExitCodeProcess(mp->hprocess,&stat) )
			goto endcmd;
		if( stat == STILL_ACTIVE ) {
			pipewrit((BYTE *)"\r",1);
			return(0);
		}
		endcmd:
		KillTimer(mp->hwnd,ID_SHELLESC);
		mp->hprocess = NULL;
		if( mp->hpiper )
			CloseHandle(mp->hpiper);
		if( mp->hpipew )
			CloseHandle(mp->hpipew);
		mp->hpiper = mp->hpipew = NULL;
		endcmd1:
		cmd[0] = 0x0d;
		cmd[1] = 0x0a;
		i = 2;
		i += getcurrentdirectoryM(&cmd[i]);
		cmd[i++] = ' ';
		cmd[i++] = '>';
		cmd[i++] = '>';
		insstr(0x12,i,cmd);
		postdo();
		return(0);	/* ｴﾗｰ */
	}
	if( *mp->ecursp != RECMARK )
		return(1);	/* 何も実行しなかった */
	i = GetEnvironmentVariable("COMSPEC",cmd,MAXCMDS);
	if( i == 0 ) {
		GetWindowsDirectory(cmd,PATHSIZE);
		fstrcpy(&cmd[3],"COMMAND.COM");
		i = 3+11;
	}
	cmd[i++] = ' ';
	cmd[i++] = '/';
	cmd[i++] = 'C';
	cmd[i++] = ' ';
	j = shgetline(&cmd[i],MAXCMDS-i-4);
	if( j == 0 )
		return(1);	/* 何も実行しなかった */
	for( p1 = &cmd[i] ; *p1 == 0x20 || *p1 == 0x09 ; p1++ ) ;
	for( p3=p1,k=0 ; *p3 && *p3 != 0x20 && *p3 != 0x09 ; p3++ ) {
		if( *p3 >= 'a' && *p3 <= 'z' )
			*p3 -= 0x20;		/* ｺﾏﾝﾄﾞを大文字に変換 */
		else if( *p3 >= 'A' && *p3 <= 'Z' ) ;
		else if( *p3 == '/' || *p3 == '-' || *p3 == '\\' ) {
			if( k == 0 && p3 > p1 )
				break;
			k++;	/* 半角英字以外の文字の数 */
		}
		else if( ctypej[*p3]&CKANJI1 ) {
			k += 2;/* 半角英字以外の文字の数 */
			p3++;
		}
		else
			k++;	/* 半角英字以外の文字の数 */
	}
	if( p3 <= p1 )
		return(1);	/* ｺﾏﾝﾄﾞ名が見つからない */
	for( p2=innercmd,k=0 ; *p2 ; k++ ) {	/* CMD.EXE の内部ｺﾏﾝﾄﾞかどうかを調べる */
		for( p = p1 ; p < p3 ; p++,p2++ ) {
			if( *p != *p2 )
				break;
		}
		if( p >= p3 && *p2 == 0x20 )
			break;
		for( ; *p2 != 0x20 ; p2++ ) ;
		for( ; *p2 == 0x20 ; p2++ ) ;
	}
	if( *p2 == '\0' ) {		/* CMD.EXE の内部ｺﾏﾝﾄﾞではない */
		if( *p1 >= 'A' && *p1 <= 'Z' && *(p1+1) == ':' && (p1+2) == p3 ) { /* ﾄﾞﾗｲﾌﾞ切替 */
			*p3 = '\0';
			getcurrentdirectoryM(path);
			if( path[1] == ':' ) {	/* ｶﾚﾝﾄﾄﾞﾗｲﾌﾞのｶﾚﾝﾄﾃﾞｨﾚｸﾄﾘを退避 */
				if( path[0] >= 'a' && path[0] <= 'z' )
					path[0] -= 0x20;
				for( k = 0 ; k < npushd ; k++ ) {
					if( path[0] == pushdir[k][0] )
						break;
				}
				if( k < npushd )
					fstrcpy(pushdir[k],path);
				else if( k < 4 ) {
					fstrcpy(pushdir[k],path);
					npushd++;
				}
			}
			for( k = 0 ; k < npushd ; k++ ) {
				if( *p1 == pushdir[k][0] )
					break;
			}
			SetErrorMode(SEM_FAILCRITICALERRORS);
			if( k < npushd )
				err = setcurrentdirectoryM(pushdir[k]);
			else
				err = setcurrentdirectoryM(p1);
			SetErrorMode(0);
			goto endcmd1;
		}
		if( !(xxxxmode&XXXX_DIRECT) )
			goto normcmd;
		/* 外部ｺﾏﾝﾄﾞを直接子ﾌﾟﾛｾｽとして実行する */
		for( p=p1,m=0 ; p < p3 ; p++ ) {
			if( ctypej[*p]&CKANJI1 )
				p++;
			else if( *p == '\\' )
				m++;
			else if( *p == '.' ) {
				if( *(p+1) != '.' )
					break;
				p++;
				m++;
			}
		}
		if( p < p3 ) {
			if( *(p+1) == 'B' && *(p+2) == 'A' && *(p+3) == 'T' && (p+4) == p3 )
				goto normcmd;
			k = 1;	/* 拡張子の指定あり */
		}
		else
			k = 0;	/* 拡張子の指定はない */
		/* ｺﾏﾝﾄﾞのﾌﾙﾊﾟｽ名を調べる */
		fstrcpy(envstr,helpnam);			/* MIW.EXE のあるﾃﾞｨﾚｸﾄﾘ */
		i = hlppos;
		envstr[i++] = ';';
		i += getcdir(&envstr[i]);			/* ｶﾚﾝﾄﾃﾞｨﾚｸﾄﾘ */
		envstr[i++] = ';';
		i += GetWindowsDirectory(&envstr[i],PATHSIZE);	/* Windowsｼｽﾃﾑﾃﾞｨﾚｸﾄﾘ */
		envstr[i++] = ';';
		i += GetSystemDirectory(&envstr[i],PATHSIZE);	/* Windows ﾃﾞｨﾚｸﾄﾘ */
		envstr[i++] = ';';
		GetEnvironmentVariable("PATH",&envstr[i],2040-i);/* 環境変数PATHで定義されたﾃﾞｨﾚｸﾄﾘ */
		p2 = envstr;
		if( m > 0 ) {
			i = 0;
			goto chkfexist;
		}
		for(  ; *p2 ; ) {
			for( p=p2,i=0 ; *p && *p != ';' ; ) {
				p4 = p;
				if( ctypej[*p]&CKANJI1 ) {
					path[i++] = *p++;
					path[i++] = *p++;
				}
				else
					path[i++] = *p++;
			}
			if( i > 0 && *p4 != '\\' )
				path[i++] = '\\';
			p2 = p;
			if( *p2 == ';' )
				p2++;
			chkfexist:
			for( p = p1 ; p < p3 ; )
				path[i++] = *p++;
			if( k == 0 ) {
				fstrcpy(&path[i],".BAT");
				if( fstat(&finddata,path) == 0 )
					goto normcmd;
				fstrcpy(&path[i],".COM");
				if( fstat(&finddata,path) == 0 )
					goto noshell;
				fstrcpy(&path[i],".EXE");
				if( fstat(&finddata,path) == 0 )
					goto noshell;
			}
			else {
				path[i] = '\0';
				if( fstat(&finddata,path) == 0 )
					goto noshell;
			}
			if( m > 0 )
				break;
		}
		i = LoadString(hinst,1348,path,200);
		insstr(0x12,i,path);
		postdo();
		goto endcmd1;
		noshell:
		fstrcpy(envstr,p3);
		i = fstrcpy(cmd,path);
		if( envstr[0] ) {
			cmd[i++] = ' ';
			fstrcpy(&cmd[i],envstr);
		}
	}
	else {		/* CMD.EXE の内部ｺﾏﾝﾄﾞ */
		if( k == 1 || k == 2 ) {	/* CHDIR CD */
			for(  ; *p3 == ' ' ; p3++ ) ;
			if( *p3 == '"' ) {
				for( p2 = (++p3) ; *p2 && *p2!='"' ; p2++ ) ;
				*p2 = '\0';
			}
			SetErrorMode(SEM_FAILCRITICALERRORS);
			err = setcurrentdirectoryM(p3);
			SetErrorMode(0);
			goto endcmd1;
		}
		else if( k == 20 ) {		/* SET */
			for(  ; *p3 == ' ' ; p3++ ) ;
			if( *p3 == '\0' )
				goto normcmd;
			for( p2 = p3 ; *p2 && *p2 != ' ' && *p2 != '=' ; p2++ ) ;
			for( p4 = p2 ; *p4 == ' ' ; p4++ ) ;
			if( *p4 != '=' )
				goto normcmd;
			*p2 = '\0';
			for( p4++ ; *p4 == ' ' ; p4++ ) ;
			if( *p3 == '"' ) {
				for( p2 = (++p3) ; *p2 && *p2 != '"' ; p2++ ) ;
				*p2 = '\0';
			}
			if( *p4 == '"' ) {
				for( p2 = (++p4) ; *p2 && *p2 != '"' ; p2++ ) ;
				*p2 = '\0';
			}
			setenvironmentvariableM(p3,p4);
			goto endcmd1;
		}
		else if( k == 14 ) {		/* PATH */
			for( ; *p3 == ' ' ; p3++ ) ;
			if( *p3 == '\0' || *p3 == ';' )
				goto normcmd;
			if( *p3 == '"' ) {
				for( p2 = (++p3) ; *p2 && *p2 != '"' ; p2++ ) ;
				*p2 = '\0';
			}
			setenvironmentvariableM("PATH",p3);
			goto endcmd1;
		}
		else if( k == 10 ) {		/* EXIT */
			if( sssmode&SYS_UNIQ )	/* SDIﾓｰﾄﾞ */
				PostMessage(hfwnd,WM_CLOSE,0,0);
			else			/* MDIﾓｰﾄﾞ */
				PostMessage(mp->hwnd,WM_CLOSE,0,0);
			mp->upflg = 0;	/* ｾｰﾌﾞは不要とする */
			return(0);
		}
		else if( k == 3 ) {		/* CLS */
			jmpadd(0,10,0x0011,LASTADDRESS);
			postdo();
			goto endcmd1;
		}
	}
	normcmd:		/* 子ﾌﾟﾛｾｽを実行 */
	/* ﾊﾟｲﾌﾟを作成 */
	readpipe1 = writepipe1 = readpipe2 = writepipe2 = NULL;
	securi.nLength = sizeof(SECURITY_ATTRIBUTES);
	securi.lpSecurityDescriptor = NULL;
	securi.bInheritHandle = TRUE;
	if( CreatePipe(&readpipe1,&writepipe1,&securi,0) ) {
		securi.nLength = sizeof(SECURITY_ATTRIBUTES);
		securi.lpSecurityDescriptor = NULL;
		securi.bInheritHandle = TRUE;
		if( !CreatePipe(&readpipe2,&writepipe2,&securi,0) ) {
			CloseHandle(readpipe1);
			readpipe1 = writepipe1 = NULL;
			readpipe2 = writepipe2 = NULL;
		}
	}
	else {
		readpipe1 = writepipe1 = NULL;
	}
	/* 子ﾌﾟﾛｾｽを実行 */
	start.cb = sizeof(STARTUPINFO);
	start.lpReserved = NULL;
	start.lpDesktop = NULL;
	start.lpTitle = NULL;
	start.dwX = 0;
	start.dwY = 0;
	start.dwXSize = 0;
	start.dwYSize = 0;
	start.dwXCountChars = 0;
	start.dwYCountChars = 0;
	start.dwFillAttribute = 0;
	start.cbReserved2 = 0;
	start.lpReserved2 = NULL;
	if( readpipe1 ) {	/* ﾊﾟｲﾌﾟで子ﾌﾟﾛｾｽと連結する */
		start.dwFlags = (STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW);
		start.wShowWindow = SW_SHOWMINIMIZED;
		start.hStdInput = readpipe2;	/* ｺﾏﾝﾄﾞ側読み出しﾊﾝﾄﾞﾙ */
		start.hStdOutput = writepipe1;	/* ｺﾏﾝﾄﾞ側書き込みﾊﾝﾄﾞﾙ */
		start.hStdError = writepipe1;	/* ｺﾏﾝﾄﾞ側書き込みﾊﾝﾄﾞﾙ */
		flag = CREATE_NEW_CONSOLE;
	}
	else {
		start.dwFlags = 0;
		start.wShowWindow = 0;
		start.hStdInput = NULL;
		start.hStdOutput = NULL;
		start.hStdError = NULL;
		flag = IDLE_PRIORITY_CLASS;
	}
	envss = (BYTE *)GetEnvironmentStrings();	/* MIFESの環境を子ﾌﾟﾛｾｽに引き継がせる */
	securi1.nLength = sizeof(SECURITY_ATTRIBUTES);
	securi1.lpSecurityDescriptor = NULL;
	securi1.bInheritHandle = ((readpipe1)?TRUE:FALSE);
	securi2.nLength = sizeof(SECURITY_ATTRIBUTES);
	securi2.lpSecurityDescriptor = NULL;
	securi2.bInheritHandle = ((readpipe1)?TRUE:FALSE);
	if( !createprocessM(
		cmd,		/* ｺﾏﾝﾄﾞﾗｲﾝ文字列(実行ﾌｧｲﾙ名を含んでもよい) */
		&securi1,	/* ﾌﾟﾛｾｽのｾｷｭﾘﾃｨ属性(SECURITY_ATTRIBUTES) */
		&securi2,	/* ﾒｲﾝｽﾚｯﾄﾞのｾｷｭﾘﾃｨ属性(SECURITY_ATTRIBUTES) */
		TRUE,		/* ﾌｧｲﾙﾊﾝﾄﾞﾙの子ﾌﾟﾛｾｽへの相続 */
		flag,		/* 各種ﾌﾗｸﾞ */
		envss,		/* 子ﾌﾟﾛｾｽの環境変数 */
		NULL,		/* 子ﾌﾟﾛｾｽの起動時のｶﾚﾝﾄﾃﾞｨﾚｸﾄﾘ */
		&start,		/* 子ﾌﾟﾛｾｽの初期ｳｨﾝﾄﾞｳ表示状態 */
		&info,		/* 子ﾌﾟﾛｾｽのﾌﾟﾛｾｽ･ﾊﾝﾄﾞﾙなどが返される */
		NULL)		/* 子ﾌﾟﾛｾｽ起動完了待機用イベントハンドル(未使用) */
		) {		/* 子ﾌﾟﾛｾｽの実行に失敗した場合 */
		if( readpipe1 ) {
			CloseHandle(readpipe1);
			CloseHandle(writepipe2);
			readpipe1 = writepipe1 = NULL;
			readpipe2 = writepipe2 = NULL;
		}
		goto endcmd1;
	}
	if( readpipe1 == NULL )	/* ﾊﾟｲﾌﾟの連結を行わなかった場合は、子ﾌﾟﾛｾｽの終了を待たない */
		goto endcmd1;
	mp->hprocess = info.hProcess;
	mp->hpiper = readpipe1;		/* MIFES側読み出しﾊﾝﾄﾞﾙ */
	mp->hpipew = writepipe2;	/* MIFES側書き込みﾊﾝﾄﾞﾙ */
	mp->kanpipe = '\0';
	mp->nofocus = 0;
	mp->idprocess = info.dwProcessId;
	SetTimer(mp->hwnd,ID_SHELLESC,100,NULL);
	SetForegroundWindow(hfwnd);	/* Windows NT/2000/XP 上では効かない */
	return(2);	/* 子ﾌﾟﾛｾｽを実行した（未終了） */
}

INT32 pipewrit(buff,i)		/* ﾊﾟｲﾌﾟにﾃｷｽﾄを書き出す */
BYTE *buff;
INT32 i;
{
	INT32 n;

	if( mp->hpipew ) {
		WriteFile(mp->hpipew,buff,i,&n,NULL);
		return(n);
	}
	else
		return(0);
}

INT32 piperead()		/* ﾊﾟｲﾌﾟからﾃｷｽﾄを読み出す */
{
	INT32 n,n1,n2;
	BYTE buff[1100],buff1[2200],*p,*q,*pmax;

	if( !PeekNamedPipe(mp->hpiper,&buff[1],1024,&n,&n1,&n2) )
		n = 0;
	if( n == 0 )
		return(0);
	ReadFile(mp->hpiper,&buff[1],n,&n1,NULL);
	/* ﾊﾟｲﾌﾟから入力した文字列(ｼﾌﾄJISﾌｫｰﾏｯﾄと見なす)をｶｰｿﾙ位置に挿入する */
	if( mp->kanpipe ) {
		buff[0] = mp->kanpipe;
		mp->kanpipe = '\0';
		p = buff;
	}
	else {
		p = &buff[1];
	}
	pmax = &buff[n1+1];
	for( q = buff1 ; p < pmax ; ) {
		if( ctypesjis[*p]&CASCII )
			*q++ = *p++;
		else if( ctypesjis[*p]&CKANJI1 ) {
			if( (p+1) >= pmax ) {
				mp->kanpipe = *p;
				break;
			}
			if( ctypesjis[*(p+1)]&CKANJI2 ) {
				*q++ = *p++;
				*q++ = *p++;
			}
			else {
				*q++ = BINMARK;
				*q++ = ctrl2token(*p);
				p++;
			}
		}
		else if( *p == 0x09 )
			*q++ = *p++;
		else if( *p == 0x0d ) {
			if( (p+1) >= pmax ) {
				mp->kanpipe = *p;
				break;
			}
			if( *(p+1) == 0x0a ) {	/* CR&LF */
				*q++ = *p++;
				*q++ = *p++;
			}
			else {			/* 単独のCR */
				*q++ = *p++;
			}
		}
		else if( *p == 0x08 ) {
			if( q > buff1 ) {
				insstr(0x12,(INT32)(q-buff1),buff1);
				postdo();
			}
			q = buff1;
			if( (p+2) < pmax && *(p+1) == ' ' && *(p+2) == 0x08 ) {
				p += 3;
				if( cleft(0) == 0 ) {
					icmask = 0x00;
					delchr(0);
				}
				postdo();
			}
			else {
				*q++ = BINMARK;
				*q++ = ctrl2token(*p);
				p++;
			}
		}
		else {
			*q++ = BINMARK;
			*q++ = ctrl2token(*p);
			p++;
		}
	}
	if( q > buff1 ) {
		insstr(0x12,(INT32)(q-buff1),buff1);
		postdo();
	}
	return(1);
}

INT32 shesctim()		/* ｼｪﾙｴｽｹｰﾌﾟ･ｳｨﾝﾄﾞｳにおけるﾀｲﾏｰ時の処理 */
{
	INT32 i;
	DWORD stat;
	BYTE path[512];

	if( mp->hprocess ) {	/* 子ﾌﾟﾛｾｽの実行中 */
		if( !GetExitCodeProcess(mp->hprocess,&stat) )
			goto endcmd;
		if( mp->hpiper )	/* ﾊﾟｲﾌﾟ中の文字ﾃﾞｰﾀを取り出す */
			i = piperead();
		if( stat != STILL_ACTIVE )
			goto endcmd;
		if( mp->nofocus < 30 ) {
			if( i == 0 && mp->focus == 0 ) {
				if( (++mp->nofocus) >= 30 ) {
					LoadString(hinst,1433,path,512);
					messageboxO(hfwnd,path,miwvermes,MB_OK|MB_ICONINFORMATION|MB_SYSTEMMODAL);
				}
			}
			else {
				if( mp->nofocus > 0 )
					mp->nofocus = 0;
			}
		}
		SetTimer(mp->hwnd,ID_SHELLESC,100,NULL);
		return(1);
	}
	else {
		endcmd:
		if( mp->hpiper ) {	/* ﾊﾟｲﾌﾟ中の文字ﾃﾞｰﾀを取り出す */
			for( ; ; ) {
				if( piperead() == 0 )
					break;
			}
		}
		KillTimer(mp->hwnd,ID_SHELLESC);
		mp->hprocess = NULL;
		if( mp->hpiper ) {
			CloseHandle(mp->hpiper);
			CloseHandle(mp->hpipew);
		}
		mp->hpiper = mp->hpipew = NULL;
		i = getcurrentdirectoryM(path);
		path[i++] = ' ';
		path[i++] = '>';
		path[i++] = '>';
		insstr(0x12,i,path);
		postdo();
		if( macwait&0x4000 ) { /* ﾏｸﾛ中からの子ﾌﾟﾛｾｽ終了待ち */
			macwait = 0x0000;
			PostMessage(hfwnd,WM_USER+180,0x00004000,0);
		}
		return(0);
	}
}

INT32 seturlfmt(buff,id)	/* URL書式を登録する(登録したIDを関数値に返す) */
BYTE *buff;	/* 登録したいURL書式(SJISﾌｫｰﾏｯﾄ) */
INT32 id;	/* 登録したい位置(-1なら指定なし) --- 空きがない場合にのみ使用 */
{
	INT32 i;

	for( i = 0 ; i < MAXURLFORMAT ; i++ ) {
		if( fstrcmp(ppmac->urlfmt[i],buff) == 0 )
			break;
	}
	if( i < MAXURLFORMAT )		/* 既に登録済み */
		return(i);
	for( i = 0 ; i < MAXURLFORMAT ; i++ ) {
		if( ppmac->urlfmt[i][0] == '\0' )
			break;
	}
	if( i < MAXURLFORMAT ) {	/* 登録に空きがある */
		fstrcpy(ppmac->urlfmt[i],buff);	/* URL書式を追加登録 */
		return(i);
	}
	if( id >= 0 && id < MAXURLFORMAT ) {
		fstrcpy(ppmac->urlfmt[id],buff);
		return(id);
	}
	i = MAXURLFORMAT-1;
	fstrcpy(ppmac->urlfmt[i],buff);
	return(i);
}

/* 範囲選択中の短い文字列を得る 					*/
/*   得られた短い文字列(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ)のﾊﾞｲﾄ数を関数値に返す		*/
INT32 getselshort(str,max)
BYTE *str;	/* 範囲選択中の短い文字列(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ)を返すﾊﾞｯﾌｧ		*/
		/* ﾇﾙが指定された場合は、短い文字列のﾊﾞｲﾄ数のみを関数値に返す	*/
INT32 max;	/* ﾋﾞｯﾄ0～15:文字列の最大長(ﾊﾞｲﾄ,1～500)			*/
		/* ﾋﾞｯﾄ16:  0=選択範囲に不当な文字を含む場合はﾇﾙ文字列とする	*/
		/*            選択範囲が指定の長さを超える場合もﾇﾙ文字列とする	*/
		/*             (不当な文字=ﾀﾌﾞ文字/改行文字/ﾊﾞｲﾅﾘ文字)		*/
		/*          1=選択範囲にある不当な文字は以下のように処理する	*/
		/*              ﾀﾌﾞ文字は半角ｽﾍﾟｰｽに変換して返す		*/
		/*              改行文字はそこで文字列の終了と見なす		*/
		/*              ﾊﾞｲﾅﾘ文字は無視する(ｽｷｯﾌﾟする)			*/
{
	INT32 add;
	BYTE *p,*q,buff[512];
	INT32 blkid;
	BYTE* ep;

	if( SELFLG < 2 )		//選択なし、箱型選択はNG
		return(0);
	if( mp->edispp == NULL )
		return(0);
	if( SELADD1 < mp->edispadd )	//選択開始が画面上に無ければNG
		return(0);
	//選択開始のポインタ取得
	blkid=mp->edispp->blkid;
	for( p=bufadr(mp, mp->edispp, NULL, &ep),add=mp->edispadd ; add < SELADD1 ; ) {
		if( ctypex[*p]&CASCII ) {
			add++;
			p++;
		}
		else if( ctypex[*p]&CKANJI1 ) {
			add += 2;
			p += 2;
		}
		else if( *p == 0x09 ) {
			add++;
			p++;
		}
		else if( ctypex[*p]&CUNIMARK ) {
			if( *p == UCS2MARK ) {
				add += 2;
				p += 3;
			}
			else {
				add += 4;
				p += 5;
			}
		}
		else if( *p == BINMARK ) {
			add++;
			p += 2;
		}
		else if( *p == RECMARK ) {
			add += (INT32)(*(p+1)&0x03);
			p += INFOSIZE1;

			if( ep <= p ) {
				if( !bufnext(mp, &blkid, &p, &ep) )
					return 0;
			}
		}
		else {		/* あり得ない */
			p++;
		}
	}

	//選択末尾orバッファ最大までコピー
	for( q = buff ; add < SELADD2 ; ) {
		if( ctypex[*p]&CASCII ) {
			add++;
			*q++ = *p++;
		}
		else if( ctypex[*p]&CKANJI1 ) {
			add += 2;
			*q++ = *p++;
			*q++ = *p++;
		}
		else if( *p == 0x09 ) {
			if( max&0x00010000 ) {
				add++;
				*q++ = 0x20;
				p++;
			}
			else
				return bufreleasen(0, mp, blkid);
		}
		else if( ctypex[*p]&CUNIMARK ) {
			if( *p == UCS2MARK ) {
				add += 2;
				*q++ = *p++;
				*q++ = *p++;
				*q++ = *p++;
			}
			else {
				add += 4;
				*q++ = *p++;
				*q++ = *p++;
				*q++ = *p++;
				*q++ = *p++;
				*q++ = *p++;
			}
		}
		else if( *p == BINMARK ) {
			if( max&0x00010000 ) {
				add++;
				p += 2;
			}
			else
				return bufreleasen(0, mp, blkid);
		}
		else if( *p == RECMARK ) {
			if( *(p+1)&0x03 ) {
				if( max&0x00010000 )
					break;
				else
					return bufreleasen(0, mp, blkid);
			}
			p += INFOSIZE1;

			if( ep <= p ) {
				if( !bufnext(mp, &blkid, &p, &ep) )
					return 0;
		}
		}
		else {		/* あり得ない */
			if( max&0x00010000 )
				p++;
			else
				return bufreleasen(0, mp, blkid);
		}
		if( q > &buff[max&0x0000ffff] ) {
			if( max&0x00010000 )
				break;
			else
				return bufreleasen(0, mp, blkid);
		}
	}
	*q = '\0';
	if( str )
		fstrcpy(str,buff);
	return bufreleasen((INT32)(q-buff), mp, blkid);
}

/* ﾃｷｽﾄ中にあるﾊﾟｽ名を取り出す(【注意】非日本語文字はﾌｧｲﾙ名として無効とする)	*/
/*  0=取り出せなかった   >0=取り出したﾊﾟｽ名/ﾌｧｲﾙ名のﾊﾞｲﾄ数			*/
INT32 getpathfromtext(path,flag)
BYTE *path;	/* 取り出した絶対ﾊﾟｽ名を返すﾊﾞｯﾌｧ */
INT32 *flag;	/* ﾋﾞｯﾄ0=1 なら < と > で囲まれていた */
		/* ﾋﾞｯﾄ1=1 なら " と " で囲まれていた */
		/* ﾋﾞｯﾄ2=1 なら ' と ' で囲まれていた */
{
	INT32 i,add;
	BYTE *p,*q,*p1,*p2,buff[PATHSIZE];
	INT32 blkid = -1;
	BYTE* ep;

	if( SELFLG > 1 ) {	/* 範囲選択中 */
		if( mp->edispp == NULL )
			return(0);
		if( SELADD1 < mp->edispadd )
			return(0);
		blkid=mp->edispp->blkid;
		for( p=bufadr(mp, mp->edispp, NULL, &ep),add=mp->edispadd ; add < SELADD1 ; ) {
			if( ctypex[*p]&CASCII ) {
				add++;
				p++;
			}
			else if( ctypex[*p]&CKANJI1 ) {
				add += 2;
				p += 2;
			}
			else if( *p == 0x09 ) {
				add++;
				p++;
			}
			else if( ctypex[*p]&CUNIMARK ) {
				if( *p == UCS2MARK ) {
					add += 2;
					p += 3;
				}
				else {
					add += 4;
					p += 5;
				}
			}
			else if( *p == BINMARK ) {
				add++;
				p += 2;
			}
			else if( *p == RECMARK ) {
				add += (INT32)(*(p+1)&0x03);
				p += INFOSIZE1;

				if( ep <= p ) {
					if( !bufnext(mp, &blkid, &p, &ep) )
						return 0;
			}
			}
			else {		/* あり得ない */
				p++;
			}
		}
		if( *p == '<' ) {
			p++;
			add++;
		}
		for( p1=p,q=buff ; add < SELADD2 ; ) {
			if( ctypex[*p]&CASCII ) {
				if( *p == '\\' || *p == ':' ) {
					add++;
					*q++ = *p++;
				}
				else if( *p == '/' ) {
					add++;
					*q++ = '\\';
					p++;
				}
				else if( ctypej[*p]&CFNAM ) {
					add++;
					*q++ = *p++;
				}
				else if( *p == '>' ) {
					if( (add+1) >= SELADD2 )
						break;
					else
						return bufreleasen(0, mp, blkid);
				}
				else
					return bufreleasen(0, mp, blkid);
			}
			else if( ctypex[*p]&CKANJI1 ) {
				add += 2;
				*q++ = *p++;
				*q++ = *p++;
			}
			else if( *p == 0x09 )
				return bufreleasen(0, mp, blkid);
			else if( ctypex[*p]&CUNIMARK ) {	/* 非日本語文字はﾌｧｲﾙ名として無効とする */
				if( *p == UCS2MARK ) {
					add += 2;
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
				}
				else {
					add += 4;
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
				}
			}
			else if( *p == BINMARK )
				return bufreleasen(0, mp, blkid);
			else if( *p == RECMARK ) {
				if( *(p+1)&0x03 )
					return bufreleasen(0, mp, blkid);
				p += INFOSIZE1;

				if( ep <= p ) {
					if( !bufnext(mp, &blkid, &p, &ep) )
						return bufreleasen(0, mp, blkid);
			}
			}
			else		/* あり得ない */
				return bufreleasen(0, mp, blkid);
			if( q >= &buff[PATHSIZE-2] )
				return bufreleasen(0, mp, blkid);
		}
	}
	else {		/* 範囲選択中でない */
		/* <"'でくくられたテキストであれば、連続するスペース、全角スペースを */
		/* ファイル名の一部とみなす */
		INT32 inquote = 0;	/* <'"を検出したか? */
		for( p=q=getlinetop(mp->ecurslp) ; p <= mp->ecursp ; ) {
			if( ctypex[*p]&CASCII ) {
				if( inquote == 0
				  && ( *p == '<' || *p == 0x22/*"*/ || *p == 0x27/*'*/) ) {
					inquote = 1;
				}
				else if( inquote != 0
				  && ( *p == '<' || *p == 0x22/*"*/ || *p == 0x27/*'*/) ) {
					inquote = 0;
				}

				if( *p == '\\' ) {
					if( *(p+1) == '\\' ) {
						q = p;
						p += 2;
					}
					else
						p++;
				}
				else if( *p == '/' ) {
					if( *(p+1) == '/' ) {
						q = p;
						p += 2;
					}
					else
						p++;
				}
				else if( *p == ':' ) {
					p++;
					q = p;
				}
				else if( *p == 0x20 ) {
					if( *(p+1) == 0x20 ) {
						for( ; *p == 0x20 ; p++ ) ;
						if( !inquote && p > mp->ecursp )
							return(0);
						if( !inquote )
							q = p;
					}
					else
						p++;
				}
				else if( *p == 0x27 /*'*/ ) {
					p++;
					q = p;
				}
				else if( ctypej[*p]&CFNAM ) {
					if( *(p+1) == ':' && ((*p>='A' && *p<='Z') || (*p>='a' && *p<='z')) ) {
						q = p;
						p += 2;
					}
					else
						p++;
				}
				else {
					p++;
					q = p;
				}
			}
			else if( ctypex[*p]&CKANJI1 ) {
				if( spacechar(p) == 2 ) {
					p += 2;
					if( !inquote )
						q = p;
				}
				else
					p += 2;
			}
			else if( *p == 0x09 ) {
				p++;
				q = p;
			}
			else if( ctypex[*p]&CUNIMARK ) {
				if( *p == UCS2MARK )
					p += 3;
				else
					p += 5;
			}
			else if( *p == BINMARK ) {
				p += 2;
				q = p;
			}
			else if( *p == RECMARK && (*(p+1) & 0x03) == 0x00 ) {
				p += INFOSIZE1;
			}
			else {		/* あり得ない */
				p++;
				q = p;
			}
		}
		if( q > mp->ecursp )
			return(0);
		for( p=p1=q,q=buff ; ; ) {
			if( ctypex[*p]&CASCII ) {
				if( *p == '\\' )
					*q++ = *p++;
				else if( *p == ':' )
					*q++ = *p++;
				else if( *p == '/' ) {
					*q++ = '\\';
					p++;
				}
				else if( *p == 0x20 ) {
					if( !inquote && *(p+1) == 0x20 )
						break;
					*q++ = *p++;
				}
				else if( *p == 0x27 )
					break;
				else if( ctypej[*p]&CFNAM )
					*q++ = *p++;
				else
					break;
			}
			else if( ctypex[*p]&CKANJI1 ) {
				if( !inquote && spacechar(p) == 2 )
					break;
				*q++ = *p++;
				*q++ = *p++;
			}
			else if( *p == 0x09 )
				break;
			else if( ctypex[*p]&CUNIMARK ) {	/* 非日本語文字はﾌｧｲﾙ名として無効とする */
				if( *p == UCS2MARK ) {
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
				}
				else {
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
				}
			}
			else if( *p == BINMARK )
				break;
			else if( *p == RECMARK ) {
				if( *(p+1)&0x03 )
					break;
				p += INFOSIZE1;
			}
			else		/* あり得ない */
				break;
			if( q >= &buff[PATHSIZE-2] )
				break;
		}
		if( p <= mp->ecursp )
			return(0);
	}
	p2 = p;
	/* 前後のｽﾍﾟｰｽをﾊﾟｰｼﾞ */
	for( ; q > buff && *(q-1) == 0x20 ; q-- ) {
		if( *(q-3) == UCS2MARK )
			break;
	}
	*q = '\0';
	for( p = buff ; *p == 0x20 ; p++ ) ;
	if( p > buff )
		fstrcpy(buff,p);
	if( buff[0] == '\0' )
		return bufreleasen(0, mp, blkid);
	if( flag ) {
		if( *(p1-1) == '<' && *p2 == '>' )
			*flag = 0x0001;
		else if( *(p1-1) == 0x22 && *p2 == 0x22 )
			*flag = 0x0002;
		else if( *(p1-1) == 0x27 && *p2 == 0x27 )
			*flag = 0x0004;
		else
			*flag = 0x0000;
	}
	if( path )
		i = fstrcpy(path,buff);
	else {
		for( q = buff ; *q ; q++ ) ;
		i = (INT32)(q-buff);
	}
	return bufreleasen(i, mp, blkid);
}

INT32 getenvmi(hdlg,flag)	/* 環境変数をｺﾝﾎﾞﾎﾞｯｸｽにｾｯﾄする */
HWND hdlg;
INT32 flag;
{
	INT32 i,j;
	BYTE *p,varname[32],varvalue[512];

	if( flag )
		SendDlgItemMessage(hdlg,IDD_ENVVAR,CB_RESETCONTENT,0,0);
	p = (BYTE *)GetEnvironmentStrings();
	for( j = 0 ; *p ; p++ ) {
		for( i = 0 ; *p && *p != '=' && i < 32 ; )
			varname[i++] = *p++;
		if( *p != '=' || i >= 32 || i == 0 ) {
			if( i == 0 ) {
				for( ; *p ; p++ ) ;
				continue;
			}
			else
				break;
		}
		varname[i] = '\0';
		for( p++,i=0 ; *p && i < 512 ; )
			varvalue[i++] = *p++;
		if( *p || i >= 512 )
			break;
		varvalue[i] = '\0';
		SendDlgItemMessage(hdlg,IDD_ENVVAR,CB_ADDSTRING,0,(LPARAM)varname);
		j++;
	}
	if( flag ) {
		SetDlgItemText(hdlg,IDD_ENVVAR,"");
		SetDlgItemText(hdlg,IDD_ENVSTR,"");
	}
	return(j);
}

INT32 setenvmi(varname,varvalue)	/* 環境変数の追加/変更/削除 */
BYTE *varname;		/* 環境変数名(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
BYTE *varvalue;		/* 環境の値(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
{
	INT32 i,j,k;

	k = setenvironmentvariableM(varname,*varvalue?varvalue:NULL);
	for( i=0,j=-1 ; i < MAXENV ; i++ ) {
		if( ppmac->envvari[i][0] == '\0' ) {
			if( j < 0 )
				j = i;
			continue;
		}
		if( fstrcmpii(ppmac->envvari[i],varname) == 0 )
			break;
	}
	if( i >= MAXENV ) {
		if( *varvalue ) {	/* 追加/変更 */
			if( j >= 0 )
				fstrcpy(ppmac->envvari[j],varname);
		}
	}
	else {
		if( *varvalue == '\0' )	/* 削除 */
			ppmac->envvari[i][0] = '\0';
	}
	return(k);
}

INT32 setincdir(flag)
INT32 flag;
{
	INT32 i;

	recaret(1);
	i = dialogboxparamO(hinst,IDD_SETINCDIR,hfwnd,SetincdirDlg,flag);
	recaret(0);
	return(i);
}

/* 指定のﾊﾟｽ名/ﾌｧｲﾙ名を既存の絶対ﾊﾟｽ名に変換する		*/
/*  0=存在しないﾊﾟｽ名/ﾌｧｲﾙ名   >0=変換した絶対ﾊﾟｽ名のﾊﾞｲﾄ数	*/
INT32 chkpathfromtext(path,perpath,flag)
BYTE *path;	/* 指定のﾊﾟｽ名/ﾌｧｲﾙ名(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ)					*/
		/*    -->取り出した既存のﾊﾟｽ名/ﾌｧｲﾙ名(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) 		*/
BYTE *perpath;	/* 存在しないﾊﾟｽ名/ﾌｧｲﾙ名(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) --- 関数値が0の時のみ有効	*/
		/* （2048ﾊﾞｲﾄ以上のﾊﾞｯﾌｧを指定すること）				*/
INT32 flag;	/* ﾋﾞｯﾄ0= 1 なら < と > で囲まれていた(環境変数を参照)			*/
		/* ﾋﾞｯﾄ1= 1 なら " と " で囲まれていた					*/
		/* ﾋﾞｯﾄ2= 1 なら ' と ' で囲まれていた					*/
		/* ﾋﾞｯﾄ3= 								*/
		/* ﾋﾞｯﾄ4= 1 なら環境変数が未設定でもﾀﾞｲｱﾛｸﾞは表示しない			*/
{
	INT32 i,j,k,ie;
	BYTE *p,*q,*pe,*pee[32],envvalue[520],dnam[PATHSIZE],ddd[PATHSIZE],fnam[PATHSIZE];

	pe = perpath;
	ie = 0;
	if( chkresvname(path) > 0 ) {	/* ﾌｧｲﾙ名に対する特殊な予約語をﾁｪｯｸ */
		if( perpath )
			fstrcpy(perpath,path);
		return(0);
	}
	/* 絶対ﾊﾟｽ名に変換 */
	if( *path == '\\' && *(path+1) == '\\' ) {	/* UNCﾊﾟｽ名 */
		fstrcpy(dnam,path);
		j = 0;
	}
	else if( *path == '\\' ) {	/* URL形式のﾊﾟｽ名( \ や / で始まるﾊﾟｽ名) */
		fstrcpy(path,path+1);
		goto redirchk;
	}
	else if( *(path+1) == ':' ) {	/* 絶対ﾊﾟｽ名 */
		fstrcpy(dnam,path);
		j = 2;
	}
	else if( flag&0x0001 ) {	/* < と > で囲まれた相対ﾊﾟｽ名/単純ﾌｧｲﾙ名 */
		redirchk:
		i = getenvironmentvariableM(envincvar,envvalue,512);
		if( i == 0 ) {	/* 環境変数 MIWINCLUDE が設定されてない */
			if( cenvdone == 0 && ( mp->langflg == 2 || mp->langflg == 3 ) ) {
				cenvdone |= 0x01;
				for( k = 0 ; k < 3 ; k++ ) {
					getpartstr(1375,k,ddd,128);
					if( fexist(ddd) == 2 ) {
						setenvmi(envincvar,ddd);
						break;
					}
				}
				if( k < 3 )
					goto redirchk;
			}
			if( !(flag&0x0010) ) {
				if( setincdir(1) )	/* 追加/変更した */
					goto redirchk;
			}
			goto redirchk2;
		}
		p = envvalue;
		redirchk1:
		for( q = dnam ; *p ; ) {
			if( ctypesjis[*p]&CASCII ) {
				if( *p == ';' )
					break;
				*q++ = *p++;
			}
			else if( ctypesjis[*p]&CKANJI1 ) {
				*q++ = *p++;
				*q++ = *p++;
			}
			else if( ctypesjis[*p]&CUNIMARK ) {
				if( *p == UCS2MARK ) {
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
				}
				else {
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
				}
			}
			else
				p++;
		}
		*q = '\0';
		if( fstrcmpii(envcdir,dnam) == 0 ) {
			if( mp->newflg == 0 )
				getcfdir(dnam,0);
			else
				getcurrentdirectoryM(dnam);
		}
		j = 3;
		goto redirchk4;
	}
	else {				/* 相対ﾊﾟｽ名/単純ﾌｧｲﾙ名 */
		redirchk2:
		if( mp->newflg == 0 ) {
			getcfdir(dnam,0);
			j = 4;
		}
		else {
			redirchk3:
			getcurrentdirectoryM(dnam);
			j = 5;
		}
		redirchk4:
		genpath(dnam,path);
		if( path[0] == '.' ) {
			if( getfullpathnameM(dnam,fnam) )
				fstrcpy(dnam,fnam);
		}
	}
	if( fexist(dnam) != 1 ) {	/* ﾌｧｲﾙが存在しない */
		if( perpath ) {
			for( i = 0 ; i < ie ; i++ ) {
				if( fstrcmpii(pee[i],dnam) == 0 )
					break;
			}
			if( i >= ie ) {
				if( ie < 8 ) {
					pee[ie++] = pe;
					pe += fstrcpy(pe,dnam);
					*pe++ = '\0';
					*pe++ = '\0';
				}
			}
		}
		if( j == 4 )
			goto redirchk3;
		else if( j == 3 ) {
			if( *p == ';' ) {
				p++;
				goto redirchk1;
			}
		}
		if( perpath ) {
			for( ; ie > 1 ; ie-- ) {
				*(pee[ie-1]-2) = 0x0d;
				*(pee[ie-1]-1) = 0x0a;
			}
		}
		return(0);
	}
	i = fstrcpy(path,dnam);
	return(i);
}

void winchg(id)		/* 分身と本物を入れ替える */
INT32 id;		/* 0=本物から分身を発生 */
			/* 1=分身と本物を入れ替え */
			/* 2=本物が非ｱｸﾃｨﾌﾞになる時の処理 */
{
	INT32 i,j,k,l,pos,err;
	LONG add,size;
	struct ETEXT *tp;

	i = mp->useflg-200;
	tp = &ppedit->etext[i];
	j = tp->useflg-50;	/* mp,j:分身  tp,i:本体 */
	if( id ) {
		add = mp->ecursadd;
		pos = mp->ecurspos;
		size = mp->size+mp->inssize;
	}
	mp->readflg = tp->readflg;
	mp->flag = tp->flag;
	mp->refmflg = tp->refmflg;
	mp->upflg = tp->upflg;
	mp->autoupflg = tp->autoupflg;
	mp->textid = tp->textid;
	mp->langflg = tp->langflg;
	mp->langid = tp->langid;
	mp->readcode = tp->readcode;
	mp->savecode = tp->savecode;
	mp->readconv = tp->readconv;
	mp->readcv1 = tp->readcv1;
	mp->readcv2 = tp->readcv2;
	mp->preunic = tp->preunic;
	mp->saveconv = tp->saveconv;
	mp->savecv1 = tp->savecv1;
	mp->savecv2 = tp->savecv2;
	mp->pppopt = tp->pppopt;
	mp->undobuff = mp->undobase+MAXREDOSIZE;
	mp->undop = mp->undobase+(DWORD)(tp->undop-tp->undobase);
	mp->redobuff = mp->undobase;
	mp->redop = mp->undobase+(DWORD)(tp->redop-tp->undobase);
	mp->undoflg = tp->undoflg;
	mp->pbase = mp->base+(DWORD)(tp->pbase-tp->base);
	mp->p = mp->base+(DWORD)(tp->p-tp->base);
	mp->pp = mp->base+(DWORD)(tp->pp-tp->base);
	mp->ebuffp = mp->base+(DWORD)(tp->ebuffp-tp->base);
	mp->ebuffep = mp->base+(DWORD)(tp->ebuffep-tp->base);
	if( tp->eendp ) {
		mp->eendp = &mp->_eendp;
		mp->eendp->blkid = tp->eendp->blkid;
		mp->eendp->p = tp->eendp->blkid == -1
				? mp->base+(DWORD)(tp->eendp->p-tp->base)
				: tp->eendp->p;
	}
	else
		mp->eendp = NULL;
	mp->ecursp = mp->base+(DWORD)(tp->ecursp-tp->base);
	mp->ecurslp = mp->base+(DWORD)(tp->ecurslp-tp->base);
	if( tp->edispp ) {
		mp->edispp = &mp->_edispp;
		mp->edispp->blkid = tp->edispp->blkid;
		mp->edispp->p = tp->edispp->blkid == -1
				? mp->base+(DWORD)(tp->edispp->p-tp->base)
				: tp->edispp->p;
	}
	else
		mp->edispp = NULL;
	mp->ecurspos = tp->ecurspos;
	mp->ecurscol = tp->ecurscol;
	mp->ecurscrr = tp->ecurscrr;
	mp->lastcol  = tp->lastcol;
	mp->edispnum = tp->edispnum;
	mp->edisplin = tp->edisplin;
	mp->edispadd = tp->edispadd;
	mp->ecursnum = tp->ecursnum;
	mp->ecurslin = tp->ecurslin;
	mp->ecursadd = tp->ecursadd;
	mp->ecursladd = tp->ecursladd;
	mp->save = tp->save;
	mp->newflg = tp->newflg;
	mp->nlmark = tp->nlmark;
	mp->slmark = tp->slmark;
	if( mp->nlmark > 0 ) {
		k = (INT32)GetWindowLong(mp->hwnd,0);
		for( l = 0 ; l < mp->nlmark ; l++ )
			ppedit->lmark[mp->slmark+l].id = k;
	}
	mp->ncmpmark = tp->ncmpmark;
	mp->nxcmpmark = tp->nxcmpmark;
	mp->offcmpmark = tp->offcmpmark;
	mp->diffcmdid = tp->diffcmdid;
	mp->diffparam = tp->diffparam;
	mp->eforblks = tp->eforblks;
	mp->ebakblks = tp->ebakblks;
	mp->prelineid = tp->prelineid;
	mp->att = tp->att;
	mp->lotime = tp->lotime;
	mp->hitime = tp->hitime;
	mp->size = tp->size;
	mp->inssize = tp->inssize;
	mp->alllines = tp->alllines;
	mp->inlib = NULL;	/* 外部ﾌﾟﾘﾌﾟﾛｾｯｻは使用しない */
	mp->outlib = NULL;	/* ﾎﾟｽﾄﾌﾟﾛｾｯｻは使用する可能性あり */
	movetxtf(mp->indll,tp->indll,32);
	movetxtf(mp->outdll,tp->outdll,32);
	movetxtf(mp->outfile,tp->outfile,PATHSIZE);
	mp->restore = tp->restore;
	movetxtf(mp->uncfile,tp->uncfile,PATHSIZE);
	movetxtf(mp->orgfile,tp->orgfile,PATHSIZE);
	mp->tagallss = tp->tagallss;
	mp->scrretadd = 0;
#ifdef SELMODENEW
	mp->selflg = 0;
#endif
#ifdef CSVEDIT
	mp->csvfile = tp->csvfile;
	mp->csvlines = tp->csvlines;
	mp->csvdispline = tp->csvdispline;
	mp->csvcurrline = tp->csvcurrline;
	mp->csvdelim = tp->csvdelim;
	mp->csvdelimsv = tp->csvdelimsv;
	mp->csvquots = tp->csvquots;
	mp->csvmaxlines = tp->csvmaxlines;
	mp->csvcursp = tp->csvcursp;
	mp->csvcursadd = tp->csvcursadd;
	mp->csvcurscrr = tp->csvcurscrr;
	mp->csvrdin = tp->csvrdin;
	mp->csvrdquo = tp->csvrdquo;
	mp->csvrdcol = tp->csvrdcol;
	mp->csvrdsize = tp->csvrdsize;
	mp->csvrderr = tp->csvrderr;
#endif
	if( sssmode&SYS_UNIQ ) {	/* SDIﾓｰﾄﾞ */
		swapdivwin(tp);
	}
	else {
		mp->fdfor = tp->fdfor;
		mp->fdbak = tp->fdbak;
		movetxtf(mp->base,tp->base,STARTBUFF+mp->editsize);	/* 編集ﾊﾞｯﾌｧ全体をｺﾋﾟｰ */
		mp->pos = tp->pos;
		mp->fd = tp->fd;
		for( err = 0 ; mp->undosize < tp->undosize ; ) {
			if( undobuffope(1) == 0 ) {
				err = 1;
				break;
			}
		}
		if( err == 0 )		/* mp->undosize = tp->undosize */
			movetxtf(mp->undobase,tp->undobase,MAXREDOSIZE+mp->undosize);	/* UNDO/REDOﾊﾞｯﾌｧ全体をｺﾋﾟｰ */
		else {
			mp->undoflg |= 0x08;
			clsundo();
		}
	}
	if( id ) {	/* 分身と本物の入れ替え */
		mp->cursx = mp->cursy = 0;
		mp->curscx = 0;
		mp->xcolpos = -1;
		if( mp->colsize != tp->colsize )
			mp->refmflg = 1;
		mp->colsize = tp->colsize;
		mp->colsize1 = tp->colsize1;
		mp->colsizeid = 0;	/* 2分割ｳｨﾝﾄﾞｳでは「ｳｨﾝﾄﾞｳ幅に自動調整」は禁止 */
		mp->tabwid = tp->tabwid;
	}
	else {		/* 本物から分身を発生 */
		mp->dispcode = tp->dispcode;
		mp->modeflga = tp->modeflga;
		mp->ntabstops = tp->ntabstops;
		for( k = 0 ; k < tp->ntabstops ; k++ )
			mp->tabstops[k] = tp->tabstops[k];
		mp->ntabstoph = tp->ntabstoph;
		for( k = 0 ; k < tp->ntabstoph ; k++ )
			mp->tabstoph[k] = tp->tabstoph[k];
		mp->bin2mode = tp->bin2mode;
		mp->bin2hex = 0;
		mp->bin2lfs = tp->bin2lfs;
		mp->bin2cx = mp->bin2cy = -1;
		mp->modeflgd = tp->modeflgd;
		mp->moderesv = tp->moderesv;
		mp->colsize = tp->colsize;
		mp->colsize1 = tp->colsize1;
		mp->colsizeid = 0;	/* 2分割ｳｨﾝﾄﾞｳでは「ｳｨﾝﾄﾞｳ幅に自動調整」は禁止 */
		mp->tabwid = tp->tabwid;
		mp->skipcol = tp->skipcol;
		mp->gskipcol = tp->gskipcol;
		sethfont(tp->ypoint,ppedit->fontnam,mp->hwnd,1);
		mp->winwid = mp->winline = mp->yycflg = 0;
		mp->cursx = mp->cursy = 0;
		mp->curscx = 0;
		mp->yunder = mp->xvertl1 = mp->xvertl2 = -1;
		mp->kakkoadd = mp->kakkocursadd = 0;
		mp->xcolpos = mp->colpos = mp->numpos = -1;
		mp->iconflg = mp->fricon = 0;
		mp->count = count++;
	}
	tp->useflg = j+200;
	mp->useflg = i+50;
	tp->colsizeid = 0;	/* 2分割するとｳｨﾝﾄﾞｳ幅に自動調整は無効に */
	tp->scrretadd = 0;
	tp->upflg = 0;
	tp->autoupflg = 0;
#ifdef SELMODENEW
	tp->selflg = 0;		/* 2分割すると範囲選択は無効に */
#endif
	if( id ) {
		if( add > mp->ecursadd )
			add = (mp->size+mp->inssize)-(size-add);
		jmpadd(pos,0,0x0000,add);	/* ｼﾞｬﾝﾌﾟ：表示はせず */
		calwskip(-1);		/* 表示開始桁(mp->skipcol)の計算 */
		pgcheck();
		mp->cursx = ((getcol1()-mp->skipcol+geteditleft(mp)+1)*mp->x1)+(mp->bin2mode?0:LEFTSPACE);
		mp->cursy = (mp->ecurspos*mp->y1)+mp->coly+mp->guidey;
		mp->xcolpos = -1;
	}
}

void setprof()	/* ｶｽﾀﾏｲｽﾞﾌｧｲﾙに書き出すﾌｧｲﾙにﾏｰｸを付ける */
{
	INT32 i,j;
	BYTE k;
	LONG cnt;
	struct ETEXT *tp;

	if( sssmode&SYS_UNIQ ) {	/* SDIﾓｰﾄﾞ */
		if( profset )		/* すでに情報は設定済 */
			return;
	}
	if( profflg < 4 )
		return;
	for( i = 0 ; i < MAXTEXT ; i++ ) {
		tp = &ppedit->etext[i];
		if( tp->useflg > 0 && tp->useflg < 150 && tp->newflg == 0 && tp->profout != 254 )
			tp->profout = 255;
		else
			tp->profout = 0;
	}
	for( k = 1 ; ; k++ ) {
		for( i=0,j=MAXTEXT,cnt=0x7fffffff ; i < MAXTEXT ; i++ ) {
			tp = &ppedit->etext[i];
			if( tp->profout != 255 )
				continue;
			if( tp->count < cnt ) {
				cnt = tp->count;
				j = i;
			}
		}
		if( j < MAXTEXT )
			ppedit->etext[j].profout = k;
		else
			break;
	}
}

HFONT setpathfont(thdc,flag)
HDC thdc;
INT32 flag;
{
	HFONT oldfont;

	if( flag == 0 ) {	/*【ﾌｧｲﾙ】ﾒﾆｭｰ中のﾌｧｲﾙ履歴の項目 */
		if( xxxxmode&XXXX_FIXFONT )
			oldfont = SelectObject(thdc,hmenufixf);
		else
			oldfont = SelectObject(thdc,hmenuf);
	}
	else if( flag == 1 ) {	/*【ﾌｧｲﾙ】ﾒﾆｭｰ中の一般項目 */
		oldfont = SelectObject(thdc,hmenuf);
	}
	else
		oldfont = NULL;
	return(oldfont);
}

INT32 getkeystr(id,buff)	/* ﾒﾆｭｰ用のｼｮｰﾄｶｯﾄｷｰ文字列を取得する */
INT32 id;
BYTE *buff;
{
	INT32 i;

	if( id >= 0 && id < MAXKEYDEF )		/* ｶｽﾀﾏｲｽﾞ可能なｷｰ操作 */
		i = getkeynam(buff,id);
	else if( id >= 300 && id < 552 )	/* 2ｽﾄﾛｰｸｷｰ操作 */
		i = getkeyss(key2ctl[(id-300)/42],(id-300)%42,buff);
	else if( id >= 1000 )			/* 固定のｷｰ操作 */
		i = fstrcpy(buff,fixkey[id-1000].keyn);
	else
		i = 0;
	return(i);
}

DWORD fontdlgdo(hdlg,flag,yp,face)	/* 「ﾌｫﾝﾄ選択」ﾀﾞｲｱﾛｸﾞの処理 */
HWND hdlg;	/* ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽ */
INT32 flag;	/* 処理ﾌﾗｸﾞ */
DWORD yp;	/* ﾋﾞｯﾄ0～7  =ﾌｫﾝﾄｻｲｽﾞ(ﾎﾟｲﾝﾄ)					*/
		/* ﾋﾞｯﾄ8～15 =最低行間(ﾋﾟｸｾﾙ)					*/
		/* ﾋﾞｯﾄ16～23=ﾌｫﾝﾄの文字ｾｯﾄID(0=日本語,,,,,)			*/
		/* ﾋﾞｯﾄ24    =ﾌﾟﾛﾎﾟｰｼｮﾅﾙﾌｫﾝﾄの使用(0=使用しない 1=使用する)	*/
BYTE *face;	/* ﾌｫﾝﾄ書体名	*/
{
	INT32 i,j,k;
	DWORD minl,idchar,point;
	HDC thdc;
	BYTE *p,*pface[MAXFONTS];
	BYTE buff[256],facebuff[MAXFONTS][MAXFNTNAM2];

	if( flag == 0 ) {	/* WM_INITDIALOG 時の処理 */
		SendDlgItemMessage(hdlg,IDD_FONTFN,CB_LIMITTEXT,62,0);
		SendDlgItemMessage(hdlg,IDD_FONTYP,CB_LIMITTEXT,3,0);
		thdc = GetDC(hfwnd);
		nface = 0;	/* 列挙数 */
		EnumFontFamilies((HDC)thdc,(LPCSTR)NULL,(FONTENUMPROCA)FontFunc,(LPARAM)facebuff);
		ReleaseDC(hfwnd,thdc);
		if( nface == 0 ) {
			SendDlgItemMessage(hdlg,IDD_FONTFN,CB_ADDSTRING,0,(LPARAM)fixface);
			nface = 1;
		}
		else {
			for( i = 0 ; i < nface ; i++ )
				pface[i] = facebuff[i];
			for( i = 0 ; i < nface ; i++ ) {	/* 書体名のｿｰﾄ */
				for( j = (i+1) ; j < nface ; j++ ) {
					if( *pface[i] == '@' ) {
						if( *pface[j] == '@' ) {
							if( aimaicmp(pface[i]+1,pface[j]+1,0) <= 0 )
								continue;
						}
					}
					else if( *pface[j] != '@' ) {
						if( aimaicmp(pface[i],pface[j],0) <= 0 )
							continue;
					}
					else
						continue;
					p = pface[i];
					pface[i] = pface[j];
					pface[j] = p;
				}
			}
			for( i = 0 ; i < nface ; i++ )
				SendDlgItemMessage(hdlg,IDD_FONTFN,CB_ADDSTRING,0,(LPARAM)pface[i]);
		}
		for( i = 0 ; i < 20 ; i++ ) {
			wsprintf(buff,"%3d",(INT32)fntpoint[i]);
			SendDlgItemMessage(hdlg,IDD_FONTYP,CB_ADDSTRING,0,(LPARAM)buff);
			ffpoint[i] = fntpoint[i];
		}
		npoint = 20;
		minl = ((yp>>8)&0x000000ff);
		if( minl < 1 )
			minl = 1;
		else if( minl > MAXFONTEXL )
			minl = MAXFONTEXL;
		LoadString(hinst,388,&buff[32],30);
		for( i = 1 ; i <= MAXFONTEXL ; i++ ) {
			wsprintf(buff,&buff[32],i);
			SendDlgItemMessage(hdlg,IDD_FONTEXL,CB_ADDSTRING,0,(LPARAM)buff);
		}
		SendDlgItemMessage(hdlg,IDD_FONTEXL,CB_SETCURSEL,(WPARAM)minl-1,0);
		idchar = ((yp>>16)&0x000000ff);
		if( idchar < 0 || idchar >= MAXCHARSET )
			idchar = 0;	/* SHIFTJIS_CHARSET */
		for( i = 0 ; i < MAXCHARSET ; i++ ) {
			getpartstr(1327,i,buff,32);
			SendDlgItemMessage(hdlg,IDD_FONTCHAR,CB_ADDSTRING,0,(LPARAM)buff);
		}
		SendDlgItemMessage(hdlg,IDD_FONTCHAR,CB_SETCURSEL,(WPARAM)idchar,0);
		SendDlgItemMessage(hdlg,IDD_FONTFIX,BM_SETCHECK,(yp&0x01000000)?1:0,0);
		if( yp&0x01000000 ) {
			LoadString(hinst,1298,buff,200);
			SetDlgItemText(hdlg,IDD_FONTMESS,buff);
		}
		else
			SetDlgItemText(hdlg,IDD_FONTMESS,"");
		dlgfont = NULL;
		calfont(hdlg,yp,face);
		return(yp);
	}
	else if( flag == 1 ) {	/* 「標準ﾌｫﾝﾄ」ﾎﾞﾀﾝの処理 */
		point = (yp&0x000000ff);
		i = ((yp>>8)&0x000000ff);
		if( i <= 0 )
			i = 1;
		j = ((yp>>16)&0x000000ff);
		k = ((yp&0x01000000)?1:0);
		fstrcpy(buff,face);
		SendDlgItemMessage(hdlg,IDD_FONTEXL,CB_SETCURSEL,i-1,0);/* 最低行間=iﾋﾟｸｾﾙ */
		SendDlgItemMessage(hdlg,IDD_FONTCHAR,CB_SETCURSEL,j,0);	/* 文字ｾｯﾄ(0=日本語) */
		SendDlgItemMessage(hdlg,IDD_FONTFIX,BM_SETCHECK,k,0);	/* ﾌﾟﾛﾎﾟｰｼｮﾅﾙﾌｫﾝﾄの使用(0=使用しない) */
		SetDlgItemText(hdlg,IDD_FONTMESS,"");			/* 警告ﾒｯｾｰｼﾞをｸﾘｱ */
		calfont(hdlg,(yp&0x01000000)|point,buff);
		SendDlgItemMessage(hdlg,IDD_FONTEXAM,WM_PAINT,0,0);	/* 見本表示を更新 */
		return(point);
	}
	else {		/* ｺﾝﾄﾛｰﾙ選択時の処理(flag==2)/ﾀﾞｲｱﾛｸﾞ終了時の処理(flag==3) */
		i = SendDlgItemMessage(hdlg,IDD_FONTFN,CB_GETCURSEL,0,0);
		j = SendDlgItemMessage(hdlg,IDD_FONTYP,CB_GETCURSEL,0,0);
		if( i == CB_ERR || j == CB_ERR ) {
			if( flag == 3 ) {	/* 終了時の処理 */
				if( dlgfont != fixfont ) {
					DeleteObject(dlgfont);
					dlgfont = NULL;
				}
			}
			return(0);
		}
		SendDlgItemMessage(hdlg,IDD_FONTFN,CB_GETLBTEXT,i,(LPARAM)buff);
		point = (DWORD)ffpoint[j];	/* 4～72 */
		i = SendDlgItemMessage(hdlg,IDD_FONTEXL,CB_GETCURSEL,0,0);
		point |= (DWORD)((i+1)<<8);	/* 1～20 */
		i = SendDlgItemMessage(hdlg,IDD_FONTCHAR,CB_GETCURSEL,0,0);
		point |= (DWORD)(i<<16);
		if( SendDlgItemMessage(hdlg,IDD_FONTFIX,BM_GETCHECK,0,0) )
			point |= 0x01000000;
		if( flag == 2 ) {	/* 選択時の処理 */
			if( point&0x01000000 ) {
				LoadString(hinst,1298,(BYTE *)facebuff,200);
				SetDlgItemText(hdlg,IDD_FONTMESS,(BYTE *)facebuff);
			}
			else
				SetDlgItemText(hdlg,IDD_FONTMESS,"");
			calfont(hdlg,point,buff);
			SendDlgItemMessage(hdlg,IDD_FONTEXAM,WM_PAINT,0,0);
			return(point);
		}
		else {			/* 終了時の処理 */
			if( dlgfont )		/* 表示例が表示されている */
				fstrcpy(face,buff);
			else
				point = 0;
			if( dlgfont != fixfont ) {
				DeleteObject(dlgfont);
				dlgfont = NULL;
			}
			return(point);
		}
	}
}

void calfont(hdlg,yp,face)	/* ﾀﾞｲｱﾛｸﾞ中の表示例で使用するﾌｫﾝﾄﾊﾝﾄﾞﾙを dlgfont に得る */
HWND hdlg;	/* ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽ */
DWORD yp;	/* ﾌｫﾝﾄｻｲｽﾞ,Etc */
BYTE *face;	/* 書体名 */
{
	INT32 i,j,k;
	BYTE buff[MAXFNTNAM];

	if( dlgfont ) {	/* 古いﾌｫﾝﾄﾊﾝﾄﾞﾙは削除 */
		if( dlgfont != fixfont )
			DeleteObject(dlgfont);
		dlgfont = NULL;
	}
	dlgfont = tryfont(yp,face);
	for( i=0,j=-1 ; i < nface ; i++ ) {
		SendDlgItemMessage(hdlg,IDD_FONTFN,CB_GETLBTEXT,i,(LPARAM)buff);
		if( fstrcmp(face,buff) == 0 )
			j = i;
	}
	if( j == -1 ) {
		if( *face ) {
			SendDlgItemMessage(hdlg,IDD_FONTFN,CB_ADDSTRING,0,(LPARAM)face);
			j = nface++;
		}
	}
	SendDlgItemMessage(hdlg,IDD_FONTFN,CB_SETCURSEL,j,0);
	for( i=0,j=-1 ; i < npoint ; i++ ) {
		if( (yp&0x000000ff) == ffpoint[i] )
			j = i;
	}
	if( j == -1 ) {
		for( i = 0 ; i < npoint ; i++ ) {
			if( (WORD)(yp&0x000000ff) < ffpoint[i] )
				break;
		}
		if( i < npoint ) {
			for( k = npoint ; k > i ; k-- )
				ffpoint[k] = ffpoint[k-1];
		}
		wsprintf(buff,"%3d",(yp&0x000000ff));
		SendDlgItemMessage(hdlg,IDD_FONTYP,CB_INSERTSTRING,i,(LPARAM)buff);
		ffpoint[i] = (WORD)(yp&0x000000ff);
		npoint++;
		j = i;
	}
	SendDlgItemMessage(hdlg,IDD_FONTYP,CB_SETCURSEL,j,0);
}

HFONT tryfont(yp,face)	/* ﾌｫﾝﾄが作成可能かどうかをﾁｪｯｸする */
DWORD yp;		/* ﾌｫﾝﾄｻｲｽﾞ,Etc */
BYTE *face;		/* 書体名 */
{
	if( (yp&0x000000ff) == fixpoint && fstrcmp(face,fixface) == 0 )
		return(fixfont);
	else
		return(chkmifnt(yp,face,0));
}

HFONT chkmifnt(yp,face,bold)
DWORD yp;	/* ﾌｫﾝﾄｻｲｽﾞ,Etc */
		/*  bit 0～ 7:フォントサイズ */
		/*  bit 8～15:最低行間 */
		/*  bit16～23:idcharsetのインデックス */
		/*  bit    24:0厳密な固定長でなければNULLを返す */
		/*  bit25～31:リストウインドウ設定(listwinfont)と衝突するので利用禁止 */
		/*  bit    31:マウスホイールによる拡大、縮小中 */
BYTE *face;	/* 書体名 */
BOOL bold;	/* 太字指定 */
{
	HFONT oldhf,hf;
	HDC hdc;
	TEXTMETRIC metric;	/* ﾌｫﾝﾄ･ﾒﾄﾘｸｽ */
	SIZE sz1,sz2,sz3;

	if( !(hf=CreateFont(0-(((yp&0x000000ff)*pixelsy)/72),0,0,0,
			bold?FW_BOLD:FW_NORMAL,0,0,0,	/* 太さ,ｲﾀﾘｯｸ,下線,ｽﾄﾗｲｸｱｳﾄ */
			idcharset[(yp>>16)&0x0000001f],
			OUT_CHARACTER_PRECIS,
			CLIP_CHARACTER_PRECIS,
			DEFAULT_QUALITY,
			FF_DONTCARE|FIXED_PITCH,
			*face?face:NULL)) )
		return(NULL);
	if( !(yp&0x01000000) ) {	/* 厳密な固定長のみの場合 */
		hdc = GetDC(NULL);
		oldhf = SelectObject(hdc,hf);
		GetTextMetrics(hdc,&metric);
		GetTextExtentPoint32(hdc,"C",1,&sz1);
		GetTextExtentPoint32(hdc,"i",1,&sz2);
		GetTextExtentPoint32W(hdc,L"Ｃ",1,&sz3);
		SelectObject(hdc,oldhf);
		ReleaseDC(NULL,hdc);
		if( sz1.cx != sz2.cx || (sz1.cx*2) != sz3.cx ) {
			DeleteObject(hf);
			return(NULL);
		}
	}
	return(hf);
}

/* ﾌｫﾝﾄﾊﾝﾄﾞﾙ dlgfont の表示例を表示する */
void fontexam(hWnd)
HWND hWnd;
{
	INT32 i,bkmode;
	HFONT ohf;
	RECT rc;
	HDC thdc;
	BYTE buff[100];
	WCHAR wbuff[100];

	thdc = GetDC(hWnd);
	GetClientRect(hWnd,&rc);
	FillRect(thdc,&rc,hbrush);
	if( dlgfont ) {
		ohf = SelectObject(thdc,dlgfont);
		getwindowtextM(hWnd,buff,100);
		i = exsjistounicode(buff,wbuff);
		bkmode = SetBkMode(thdc,TRANSPARENT);
		SetTextColor(thdc,colortab[1]);
		TextOutW(thdc,4,4,wbuff,i);
		SetBkMode(thdc,bkmode);
	}
	else {
		ohf = SelectObject(thdc,GetStockObject(SYSTEM_FONT));
		LoadString(hinst,171,buff,100);
		SetTextColor(thdc,0x00ffffff);
		SetBkColor(thdc,0x00000000);
		DrawText(thdc,buff,-1,&rc,DT_CENTER|DT_NOPREFIX);
	}
	SelectObject(thdc,ohf);
	ReleaseDC(hWnd,thdc);
}

void aboutdraw(hWnd)	/* 「ﾊﾞｰｼﾞｮﾝ情報」ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽ中のMIFESｲﾒｰｼﾞ表示 */
HWND hWnd;
{
	int x1,x2,y1;
	RECT rc;
	HDC thdc;
	HICON icon;

	thdc = GetDC(hWnd);
	GetClientRect(hWnd,&rc);
	x1 = (rc.right-32)/2;
	x2 = (rc.right-96)/6;
	y1 = (rc.bottom-64)/6;
	icon = LoadIcon(hinst,MAKEINTRESOURCE(ICON_FRAME));
	DrawIcon(thdc,x1,y1,icon);
	icon = LoadIcon(hinst,MAKEINTRESOURCE(ICON_MDI));
	DrawIcon(thdc,x2,(y1*5)+32,icon);
	DrawIcon(thdc,(x2*3)+32,(y1*5)+32,icon);
	DrawIcon(thdc,(x2*5)+64,(y1*5)+32,icon);
	MoveToEx(thdc,x1+15,y1+34,NULL);
	LineTo(thdc,x1+15,(y1*5)+30);
	MoveToEx(thdc,x2+15,(y1*5)+30,NULL);
	LineTo(thdc,x2+15,(y1*3)+30);
	LineTo(thdc,(x2*5)+79,(y1*3)+30);
	LineTo(thdc,(x2*5)+79,(y1*5)+30);
	ReleaseDC(hWnd,thdc);
}

INT32 getstrtime(flag,buff,idtime,ptime1,ptime2)	/* ﾀｲﾑｽﾀﾝﾌﾟ条件文字列を返す */
INT32 flag;	/* 0=簡略表示(ﾌｧｲﾙの検索のﾒﾆｭｰ項目用) 						*/
		/* 1=簡略表示(ﾀｲﾑｽﾀﾝﾌﾟ条件のｺﾝﾎﾞﾎﾞｯｸｽ内項目用) -- ｸﾞﾛｰﾊﾞﾙ検索系ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽ用	*/
		/* 2=簡略表示(ﾀｲﾑｽﾀﾝﾌﾟ条件のｺﾝﾎﾞﾎﾞｯｸｽ内項目用) --「ﾌｧｲﾙの検索」ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽ用	*/
		/* 3=ﾌﾙ表示(ﾌｧｲﾙの検索/ｸﾞﾛｰﾊﾞﾙ検索の条件表示用) 				*/
BYTE *buff;	/* ﾀｲﾑｽﾀﾝﾌﾟ条件文字列を返すﾊﾞｯﾌｧ */
INT32 idtime;	/* ﾀｲﾑｽﾀﾝﾌﾟ条件ID */
SYSTEMTIME *ptime1;	/* ﾀｲﾑｽﾀﾝﾌﾟ条件(開始時刻) */
SYSTEMTIME *ptime2;	/* ﾀｲﾑｽﾀﾝﾌﾟ条件(終了時刻) */
{
	INT32 i;
	BYTE area1[80],area2[32];
	SYSTEMTIME sss1,sss2;
	FILETIME fff1,fff2;

	if( flag == 3 )
		i = getpartstr(1358,0,buff,64);		/* 「ﾀｲﾑｽﾀﾝﾌﾟ条件=」*/
	else
		i = 0;
	if( idtime == 1 ) {
		SystemTimeToFileTime(ptime1,&fff1);
		FileTimeToLocalFileTime(&fff1,&fff2);
		FileTimeToSystemTime(&fff2,&sss1);
		SystemTimeToFileTime(ptime2,&fff1);
		FileTimeToLocalFileTime(&fff1,&fff2);
		FileTimeToSystemTime(&fff2,&sss2);
		getpartstr(1144,flag,area1,80);		/* flag=0～3 */
		if( flag == 0 || flag == 1 ) {
			sss1.wYear %= 100;
			sss2.wYear %= 100;
		}
		i += wsprintf(buff+i,area1,
			sss1.wYear,sss1.wMonth,sss1.wDay,sss1.wHour,sss1.wMinute,
			sss2.wYear,sss2.wMonth,sss2.wDay,sss2.wHour,sss2.wMinute);
	}
	else {
		getpartstr(1358,1,area1,64);		/* 「最近～間に更新したﾌｧｲﾙ」 */
		getpartstr(1358,idtime+2,area2,32);
		i += wsprintf(buff+i,area1,area2);
	}
	return(i);
}

INT32 getcmptime(idtime,ptime1,ptime2,pstarttime,pendtime)
INT32 idtime;
SYSTEMTIME *ptime1;
SYSTEMTIME *ptime2;
FILETIME *pstarttime;
FILETIME *pendtime;
{
	static WORD mdays[12] = { 31,28,31,30,31,30,31,31,30,31,30,31 };
	SYSTEMTIME sss;

	if( idtime == 0 )	/* ﾀｲﾑｽﾀﾝﾌﾟ条件なし */
		return(0);
	else if( idtime == 1 ) {/* 指定の期間に更新したﾌｧｲﾙ */
		SystemTimeToFileTime(ptime1,pstarttime);
		SystemTimeToFileTime(ptime2,pendtime);
	}
	else {			/* 最近更新したﾌｧｲﾙ */
		/* うるう年は無視(2月は常に28日とする) */
		GetSystemTime(&sss);
		if( idtime == 2 ) {		/* 1時間 */
			if( sss.wHour >= 1 )
				sss.wHour -= 1;
			else if( sss.wDay >= 2 ) {
				sss.wDay -= 1;
				sss.wHour = 23;
			}
			else if( sss.wMonth >= 2 ) {
				sss.wMonth -= 1;
				sss.wDay = mdays[sss.wMonth-1];
				sss.wHour = 23;
			}
			else {
				sss.wYear -= 1;
				sss.wMonth = 12;
				sss.wDay = mdays[sss.wMonth-1];
				sss.wHour = 23;
			}
		}
		else if( idtime == 3 ) {	/* 3時間 */
			if( sss.wHour >= 3 )
				sss.wHour -= 3;
			else if( sss.wDay >= 2 ) {
				sss.wDay -= 1;
				sss.wHour += (24-3);
			}
			else if( sss.wMonth >= 2 ) {
				sss.wMonth -= 1;
				sss.wDay = mdays[sss.wMonth-1];
				sss.wHour += (24-3);
			}
			else {
				sss.wYear -= 1;
				sss.wMonth = 12;
				sss.wDay = mdays[sss.wMonth-1];
				sss.wHour += (24-3);
			}
		}
		else if( idtime == 4 ) {	/* 1日 */
			if( sss.wDay >= 2 )
				sss.wDay -= 1;
			else if( sss.wMonth >= 2 ) {
				sss.wMonth -= 1;
				sss.wDay = mdays[sss.wMonth-1];
			}
			else {
				sss.wYear -= 1;
				sss.wMonth = 12;
				sss.wDay = mdays[sss.wMonth-1];
			}
		}
		else if( idtime == 5 ) {	/* 1週間 */
			if( sss.wDay >= 8 )
				sss.wDay -= 7;
			else if( sss.wMonth >= 2 ) {
				sss.wMonth -= 1;
				sss.wDay += (mdays[sss.wMonth-1]-7);
			}
			else {
				sss.wYear -= 1;
				sss.wMonth = 12;
				sss.wDay += (mdays[sss.wMonth-1]-7);
			}
		}
		else if( idtime == 6 ) {	/* 1ヶ月 */
			if( sss.wMonth >= 2 )
				sss.wMonth -= 1;
			else {
				sss.wYear -= 1;
				sss.wMonth += 11;
			}
		}
		else {				/* 1年 */
			sss.wYear -= 1;
		}
		SystemTimeToFileTime(&sss,pstarttime);
	}
	return(1);
}

/* 「ﾀｲﾑｽﾀﾝﾌﾟ条件」ｺﾝﾎﾞﾎﾞｯｸｽの操作 */
INT32 timestampope(hdlg,id,flag,idtime,ptime1,ptime2)
HWND hdlg;
INT32 id;
INT32 flag;
INT32 idtime;
SYSTEMTIME *ptime1;
SYSTEMTIME *ptime2;
{
	INT32 i,j,k,l,m,n;
	SYSTEMTIME sss1,sss2,*psss;
	FILETIME fff,fff1,fff2;
	BYTE buff[128],buff1[64],buff2[64];

	if( flag == 0 || flag == 10 ) {	/* 「ﾀｲﾑｽﾀﾝﾌﾟ条件」ｺﾝﾎﾞﾎﾞｯｸｽの初期化(0=ﾌｧｲﾙの検索ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽ  10=ｸﾞﾛｰﾊﾞﾙ系ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽ) */
		getpartstr(1358,2,buff,64);	/* ﾀｲﾑｽﾀﾝﾌﾟ条件なし */
		SendDlgItemMessage(hdlg,id,CB_ADDSTRING,0,(LPARAM)buff);
		getpartstr(1358,1,buff1,64);
		for( i = 2 ; i < 8 ; i++ ) {	/* 最近～間に更新したファイル */
			getpartstr(1358,i+2,buff2,64);
			wsprintf(buff,buff1,buff2);
			SendDlgItemMessage(hdlg,id,CB_ADDSTRING,0,(LPARAM)buff);
		}
		getpartstr(1358,3,buff,64);	/* ﾀｲﾑｽﾀﾝﾌﾟ条件の設定... */
		SendDlgItemMessage(hdlg,id,CB_ADDSTRING,0,(LPARAM)buff);
		if( idtime == 1 ) {
			getstrtime((flag==10)?1:2,buff,idtime,ptime1,ptime2);	/* flag=10 → ｸﾞﾛｰﾊﾞﾙ系ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽのｺﾝﾎﾞﾎﾞｯｸｽ */
			SendDlgItemMessage(hdlg,id,CB_INSERTSTRING,0,(LPARAM)buff);
			j = 0;
			m = 1;
		}
		else {
			if( idtime == 0 )
				j = 0;
			else if( idtime > 1 )
				j = idtime-1;
			m = 0;
		}
		SendDlgItemMessage(hdlg,id,CB_SETCURSEL,j,0);
		return(m);
	}
	else if( flag == 1 ) {	/* 「ﾀｲﾑｽﾀﾝﾌﾟ条件」ｺﾝﾎﾞﾎﾞｯｸｽから設定を取得 */
		k = idtime;
		j = SendDlgItemMessage(hdlg,id,CB_GETCURSEL,0,0);
		if( j == CB_ERR )
			j = 0;
		else if( j < k )
			j = 1;	/* 「j=1」の時の詳しい開始/終了時刻は呼び出し元のﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽが記憶している */
		else if( j == k )
			j = 0;
		else if( j < (k+1+6) )
			j = j-k-1+2;
		else		/* あり得ないが */
			j = 0;
		return(j);	/* 「j=1」の時の詳しい開始/終了時刻は呼び出し元のﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽが記憶している */
	}
	else if( flag == 2 ) {	/* 「ﾀｲﾑｽﾀﾝﾌﾟ条件の設定」ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽの初期化 --- 初期値は常に現在時刻 */
		GetLocalTime(&sss1);
		movetxtf((BYTE *)&sss2,(BYTE *)&sss1,sizeof(SYSTEMTIME));
		for( i = 0 ; i < 10 ; i++ ) {
			if( i < 5 )
				psss = &sss1;
			else
				psss = &sss2;
			m = (i%5);
			if( m == 0 ) {
				j = 4;
				k = 1980;
				l = 2099;
				n = (INT32)psss->wYear;
			}
			else if( m == 1 ) {
				j = 2;
				k = 1;
				l = 12;
				n = (INT32)psss->wMonth;
			}
			else if( m == 2 ) {
				j = 2;
				k = 1;
				l = 31;
				n = (INT32)psss->wDay;
			}
			else if( m == 3 ) {
				j = 2;
				k = 0;
				l = 23;
				n = (INT32)psss->wHour;
			}
			else {
				j = 2;
				k = 0;
				l = 59;
				n = (INT32)psss->wMinute;
			}
			SendDlgItemMessage(hdlg,id+i,EM_LIMITTEXT,j,0);
			SendDlgItemMessage(hdlg,id+i+10,UDM_SETBUDDY,(WPARAM)GetDlgItem(hdlg,id+i),0);
			SendDlgItemMessage(hdlg,id+i+10,UDM_SETBASE,10,0);
			SendDlgItemMessage(hdlg,id+i+10,UDM_SETRANGE,0,MAKELPARAM(l,k));
			wsprintf(buff,"%d",n);
			SetDlgItemText(hdlg,id+i,buff);
		}
		return(1);
	}
	else if( flag == 3 ) {	/* 「ﾀｲﾑｽﾀﾝﾌﾟ条件の設定」ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽから設定を取得(関数値が負の値ならｴﾗｰ) */
		for( i = 0 ; i < 10 ; i++ ) {
			GetDlgItemText(hdlg,id+i,buff,8);
			if( (j=matoi(buff,NULL)) < 0 )
				break;
			if( i == 0 )
				sss1.wYear = j;
			else if( i == 1 )
				sss1.wMonth = j;
			else if( i == 2 )
				sss1.wDay = j;
			else if( i == 3 )
				sss1.wHour = j;
			else if( i == 4 )
				sss1.wMinute = j;
			else if( i == 5 )
				sss2.wYear = j;
			else if( i == 6 )
				sss2.wMonth = j;
			else if( i == 7 )
				sss2.wDay = j;
			else if( i == 8 )
				sss2.wHour = j;
			else if( i == 9 )
				sss2.wMinute = j;
		}
		if( i < 10 )	/* 指定ｴﾗｰ */
			return(-1);
		sss1.wSecond = 0;		/* 開始時刻は正確には00.000秒から */
		sss1.wMilliseconds = 0;
		sss2.wSecond = 59;		/* 終了時刻は正確には59.999秒まで */
		sss2.wMilliseconds = 999;
		if( !SystemTimeToFileTime(&sss1,&fff1) )
			return(-2);
		if( !SystemTimeToFileTime(&sss2,&fff2) )
			return(-2);
		if( CompareFileTime(&fff1,&fff2) > 0 )
			return(-3);
		LocalFileTimeToFileTime(&fff1,&fff);
		FileTimeToSystemTime(&fff,ptime1);
		LocalFileTimeToFileTime(&fff2,&fff);
		FileTimeToSystemTime(&fff,ptime2);
		return(1);
	}
	return(0);
}

INT32 getextpppstr(hdlg,id,buff)	/* 外部ﾌﾟﾘ/ﾎﾟｽﾄﾌﾟﾛｾｯｻの説明文を得る */
HWND hdlg;	/* ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽ */
INT32 id;	/* ﾘｽﾄﾎﾞｯｸｽ中のID */
BYTE *buff;	/* 説明文を得るﾊﾞｯﾌｧ */
{
	INT32 i,j;
	HINSTANCE hlib;
	BYTE path[PATHSIZE];

	if( id == 0 )	/* ﾎﾟｽﾄﾌﾟﾛｾｯｻなし */
		i = LoadString(hinst,1300,buff,500);
	else {		/* 外部ﾌﾟﾘ/ﾎﾟｽﾄﾌﾟﾛｾｯｻ */
		j = fstrcpy(path,cdirec);
		j += SendDlgItemMessage(hdlg,IDD_OPENPPP,LB_GETTEXT,id,(LPARAM)&path[j]);
		fstrcpy(&path[j],".PPP");
		if( (hlib=loadlibraryM(path)) ) {
			i = j = LoadString(hinst,1313,buff,48);
			i += LoadString(hlib,0,buff+j,500-j);
			FreeLibrary(hlib);
		}
		else {
			*buff = '\0';
			i = 0;
		}
	}
	return(i);
}

INT32 fillppplst(hdlg,id,l,k,flag)		/* ﾌﾟﾘ/ﾎﾟｽﾄﾌﾟﾛｾｯｻをｾｯﾄする(選択項目IDを返す) */
HWND hdlg;	/* ﾀﾞｲｱﾛｸﾞのﾊﾝﾄﾞﾙ					*/
INT32 id;	/* ﾘｽﾄﾎﾞｯｸｽ または ｺﾝﾎﾞﾎﾞｯｸｽ のID			*/
INT32 l;	/* 既に追加済の項目数( 0 or 1=「自動設定」が追加済み)	*/
INT32 k;	/* 選択項目ID(-1なら未定)				*/
INT32 flag;	/* 0=ﾘｽﾄﾎﾞｯｸｽ  1=ｺﾝﾎﾞﾎﾞｯｸｽ				*/
{
	INT32 j,n,m1,m2,lenppp[256];
	HANDLE hfind;
	WIN32_FIND_DATA finddata;
	BYTE buff[PATHSIZE],miwppp[256][32];

	if( flag == 0 ) {	/* ﾘｽﾄﾎﾞｯｸｽ */
		m1 = LB_ADDSTRING;
		m2 = LB_SETCURSEL;
	}
	else {			/* ｺﾝﾎﾞﾎﾞｯｸｽ */
		m1 = CB_ADDSTRING;
		m2 = CB_SETCURSEL;
	}
	for( j = 0 ; j < pppinfocnt ; j++ ) {
		INT32 idx = pppinfoidx[j];
		SendDlgItemMessage(hdlg,id,m1,0,(LPARAM)pppinfo[idx].regname);
		if( k < 0 ) {
			if( fstrcmp(pppinfo[idx].regname,openppp) == 0 )
				k = l;
		}
		l++;
	}
	j = fstrcpy(buff,cdirec);
	fstrcpy(&buff[j],"*.PPP");
	hfind = findfirstfileM(buff,&finddata);
	n = 0;
	if( hfind != INVALID_HANDLE_VALUE ) {
		for( ; ; ) {
			if( finddata.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_TEMPORARY) )
				goto nnff;
			lenppp[n] = fstrcpy(miwppp[n],finddata.cFileName);
			n++;
			nnff:
			if( findnextfileM(hfind,&finddata) == FALSE )
				break;
		}
		FindClose(hfind);
	}
	for( j = 0 ; j < n ; j++ ) {
		if( k < 0 ) {
			if( fstrcmpii(miwppp[j],openppp) == 0 )
				k = l;
		}
		miwppp[j][lenppp[j]-4] = '\0';
		SendDlgItemMessage(hdlg,id,m1,0,(LPARAM)miwppp[j]);
		l++;
	}
	SendDlgItemMessage(hdlg,id,m2,k,0);
	return(k);
}

INT32 getpppname(hwndcb,type,id,flag,buff)
HWND hwndcb;		/* ｺﾝﾄﾛｰﾙのﾊﾝﾄﾞﾙ */
INT32 type;		/* ｺﾝﾄﾛｰﾙのﾀｲﾌﾟ( 0=自動設定,SHIFT_JIS,,,   1=SHIFT_JIS,,, )	*/
INT32 id;		/* ﾘｽﾄ中の指定する項目のID					*/
INT32 flag;		/* ﾋﾞｯﾄ0: 0=ﾘｽﾄﾎﾞｯｸｽ  1=ｺﾝﾎﾞﾎﾞｯｸｽ				*/
			/* ﾋﾞｯﾄ4: 0=ﾌﾟﾘ/ﾎﾟｽﾄﾌﾟﾛｾｯｻ名を返す  1=ﾘｽﾄ中の項目名を返す	*/
BYTE *buff;		/* ﾌﾟﾘ/ﾎﾟｽﾄﾌﾟﾛｾｯｻ名または項目名を返すﾊﾞｯﾌｧ			*/
{
	INT32 i,n;

	if( flag&0x01 )		/* ｺﾝﾎﾞﾎﾞｯｸｽ */
		i = SendMessage(hwndcb,CB_GETLBTEXT,id,(LPARAM)buff);
	else			/* ﾘｽﾄﾎﾞｯｸｽ */
		i = SendMessage(hwndcb,LB_GETTEXT,id,(LPARAM)buff);
	if( flag&0x10 )	/* ﾘｽﾄ中の項目名を返す */
		return(i);
	if( type == 0 ) {
		n = 1;
		if( id == 0 ) {		/* 自動設定 */
			*buff = '\0';
			return(0);
		}
		else if( id == 1 ) {	/* SHIFT_JIS(ﾌﾟﾘﾌﾟﾛｾｯｻなし) */
			*buff = ' ';
			*(buff+1) = '\0';
			return(1);
		}
	}
	else {
		n = 0;
		if( id == 0 ) {		/* SHIFT_JIS(ﾎﾟｽﾄﾌﾟﾛｾｯｻなし) */
			*buff = '\0';
			return(0);
		}
	}
	if( id >= (n+MAXINPPPNEW) )	/* 外部ﾌﾟﾘ/ﾎﾟｽﾄﾌﾟﾛｾｯｻ */
		i += fstrcpy(buff+i,".PPP");
	return(i);
}

INT32 getpppcont(hwndcb,type,id,flag,mess)	/* 文字ｺｰﾄﾞ/ﾌﾟﾘ/ﾎﾟｽﾄﾌﾟﾛｾｯｻの内容説明を得る */
HWND hwndcb;	/* ｺﾝﾄﾛｰﾙのﾊﾝﾄﾞﾙ			*/
INT32 type;	/* ｺﾝﾄﾛｰﾙのﾀｲﾌﾟ				*/
		/* 0=自動設定,SHIFT_JIS,,, (「ﾌｧｲﾙを開く」、「ﾌｧｲﾙを開き直す」、「拡張子定義のﾌﾟﾘ/ﾎﾟｽﾄﾌﾟﾛｾｯｻの設定」)	*/
		/* 1=SHIFT_JIS,,, (「保存時のﾎﾟｽﾄﾌﾟﾛｾｯｻの設定」ﾀﾞｲｱﾛｸﾞ)							*/
INT32 id;	/* ﾘｽﾄ中の選択項目ID				*/
INT32 flag;	/* 0=ﾘｽﾄﾎﾞｯｸｽ  1=ｺﾝﾎﾞﾎﾞｯｸｽ			*/
BYTE *mess;	/* 内容説明を返すﾊﾞｯﾌｧ(512ﾊﾞｲﾄ以上のﾊﾞｯﾌｧ)	*/
{
	BYTE pppname[128];

	if( type == 0 ) {
		if( id == 0 )	/* 自動設定 */
			return(getpppstr((dlgid==8)?(-3):(-2),NULL,mess));
		id--;
	}
	if( id < MAXINPPPNEW ) {	/* 文字ｺｰﾄﾞ(内部ﾌﾟﾘ/ﾎﾟｽﾄﾌﾟﾛｾｯｻ) */
		return(getpppstr(id,NULL,mess));
	}
	else {				/* 外部ﾌﾟﾘ/ﾎﾟｽﾄﾌﾟﾛｾｯｻ */
		SendMessage(hwndcb,(flag==0)?LB_GETTEXT:CB_GETLBTEXT,(type==0)?(id+1):id,(LPARAM)pppname);
		return(getpppstr(-1,pppname,mess));
	}
}

void pppcombo(id1,id2,id3,hdlg,lparam)
INT32 id1;
INT32 id2;
INT32 id3;
HWND hdlg;
LPARAM lparam;
{
	INT32 i,n,listtype,combo;
	BYTE buff[384];
	RECT rc;
	MEASUREITEMSTRUCT *pmitem;
	DRAWITEMSTRUCT *pwitem;
	COLORREF c0,c1;
	HFONT oldfont;
	HPEN hpen,oldpen;
	HDC thdc;

	if( id3 < 0 ) {
		pmitem = (MEASUREITEMSTRUCT *)lparam;
		GetClientRect(GetDlgItem(hdlg,id1),&rc);
		pmitem->itemWidth = rc.right-rc.left;
		pmitem->itemHeight = dlgfy+1;
		return;
	}
	pwitem = (DRAWITEMSTRUCT *)lparam;
	thdc = pwitem->hDC;
	if( pwitem->itemAction == ODA_DRAWENTIRE ) {
		dddiip:
		if( dlgid == 0 || dlgid == 3 || dlgid == 5 ) {	/* 開く、挿入、開く */
			listtype = 0;
			combo = 0x01;
			n = 1;
		}
		else if( dlgid == 1 || dlgid == 2 ) {	/* 保存、変更 */
			listtype = 1;
			combo = 0x01;
			n = 0;
		}
		else if( dlgid == 4 ) {		/* finput()関数 */
			buff[0] = '\0';
			n = i = 0;
			goto ddditem;
		}
		else if( dlgid == 6 ) {		/* ﾎﾟｽﾄﾌﾟﾛｾｯｻ設定 */
			listtype = 1;
			combo = 0x00;
			n = 0;
		}
		else if( dlgid == 7 ) {		/* 編集やり直し */
			listtype = 0;
			combo = 0x01;
			n = 1;
		}
		else {				/* 拡張子定義の文字ｺｰﾄﾞ/ﾌﾟﾘﾌﾟﾛｾｯｻの設定 */
			listtype = 0;
			combo = 0x00;
			n = 1;
		}
		i = getpppname(GetDlgItem(hdlg,id1),listtype,pwitem->itemID,combo|0x10,buff);
		if( pwitem->itemState&ODS_SELECTED ) {
			getpppcont(GetDlgItem(hdlg,id1),listtype,pwitem->itemID,combo,ffdump.buff);
			if( id2 >= 0 ) {
				setdump(-4,GetDlgItem(hdlg,id3),"",&ffdump);
				SetScrollRange(GetDlgItem(hdlg,id2),SB_CTL,0,ffdump.ldump-4,TRUE);
				SetScrollPos(GetDlgItem(hdlg,id2),SB_CTL,ffdump.sdump,TRUE);
				SendDlgItemMessage(hdlg,id3,WM_PAINT,0,0);
			}
			else {
				SetDlgItemText(hdlg,id3,ffdump.buff);
			}
		}
		ddditem:
		rc.left = pwitem->rcItem.left;
		rc.top = pwitem->rcItem.top;
		rc.right = pwitem->rcItem.right;
		rc.bottom = pwitem->rcItem.bottom-1;
		if( pwitem->itemState&ODS_SELECTED ) { /* 選択項目 */
			c0 = GetSysColor(COLOR_HIGHLIGHT);
			c1 = GetSysColor(COLOR_HIGHLIGHTTEXT);
		}
		else {
			c0 = GetSysColor(COLOR_WINDOW);
			c1 = GetSysColor(COLOR_WINDOWTEXT);
		}
		SetBkColor(thdc,c0);
		SetTextColor(thdc,c1);
		oldfont = SelectObject(thdc,hdlgf);
		ExtTextOut(thdc,pwitem->rcItem.left+2,pwitem->rcItem.top,ETO_OPAQUE,&rc,buff,i,NULL);
		SelectObject(thdc,oldfont);
		if( (INT32)pwitem->itemID == (n+MAXINPPPNEW-1) ) {
			hpen = CreatePen(PS_SOLID,1,colortab[47]);
			oldpen = SelectObject(thdc,hpen);
			MoveToEx(thdc,0,rc.bottom,NULL);
			LineTo(thdc,pwitem->rcItem.right,rc.bottom);
			SelectObject(thdc,oldpen);
			DeleteObject(hpen);
		}
	}
	else if( pwitem->itemAction == ODA_SELECT ) {
		goto dddiip;
	}
	else if( pwitem->itemAction == ODA_FOCUS ) {
		rc.left = pwitem->rcItem.left;
		rc.top = pwitem->rcItem.top;
		rc.right = pwitem->rcItem.right;
		rc.bottom = pwitem->rcItem.bottom-1;
		DrawFocusRect(thdc,&rc);
	}
}

void setbtnface(hdlg,id,flag)
HWND hdlg;
INT32 id;
INT32 flag;
{
	BYTE *p,face[80];

	getpartstr(38,0,face,48);
	for( p = face ; *p && *p != '=' ; p++ ) ;
	if( *p )
		p++;
	getfiletype(p,flag);
	SetDlgItemText(hdlg,id,face);
}

INT32 getfiletype(p,flag)
BYTE *p;
INT32 flag;
{
	if( flag < 0 )
		return(fstrcpy(p,"未選択"));
	else if( flag == IDSJIS )	/* ｼﾌﾄJISｺｰﾄﾞﾌｧｲﾙ */
		return(fstrcpy(p,pppinfo[0].regname));
	else if( flag >= IDBINARY )	/* ﾊﾞｲﾅﾘﾌｧｲﾙ */
		return(getpartstr(1022,2,p,32));
	else				/* 内部ﾌﾟﾘﾌﾟﾛｾｯｻで変換すべきﾌｧｲﾙ */
		return(fstrcpy(p,pppinfo[flag].regname));
}

void clsdetail(hdlg,pffdump,id1,id2,id3)	/* 「ﾌｧｲﾙを開く」ﾀﾞｲｱﾛｸﾞでのﾌﾟﾚﾋﾞｭｰ表示をｸﾘｱする */
HWND hdlg;		/* 「ﾌｧｲﾙを開く」ﾀﾞｲｱﾛｸﾞ */
struct FFDUMP *pffdump;	/* ﾌﾟﾚﾋﾞｭｰ用の情報を格納する構造体へのﾎﾟｲﾝﾀｰ */
INT32 id1;		/* ﾌﾟﾚﾋﾞｭｰｳｨﾝﾄﾞｳ上のﾀｲﾄﾙのｺﾝﾄﾛｰﾙID */
INT32 id2;		/* ﾌﾟﾚﾋﾞｭｰｳｨﾝﾄﾞｳのｺﾝﾄﾛｰﾙID */
INT32 id3;		/* ﾌﾟﾚﾋﾞｭｰｳｨﾝﾄﾞｳ右隣の垂直ｽｸﾛｰﾙﾊﾞｰのｺﾝﾄﾛｰﾙID */
{
	pffdump->path[0] = '\0';
	pffdump->id = IDSJIS;
	pffdump->bom = 0;
	pffdump->ndump = 0;
	pffdump->ldump = 0;
	pffdump->sdump = 0;
	pffdump->iblock = 0;
	pffdump->nblock = 0;
	SetScrollPos(GetDlgItem(hdlg,id3),SB_CTL,0,TRUE);
	setbtnface(hdlg,id1,-1);
	SendDlgItemMessage(hdlg,id2,WM_PAINT,0,0);
}

void dispcolok(hwnd,id)		/* ｷｰﾜｰﾄﾞ色の見本画面表示 */
HWND hwnd;
INT32 id;
{
	INT32 i,j,x,y,bkmode;
	BYTE buff[64];
	HDC thdc;
	RECT rc;
	HFONT holdfont;

	thdc = GetDC(hwnd);
	GetClientRect(hwnd,&rc);
	x = rc.right-rc.left;
	FillRect(thdc,&rc,hbrush);
	bkmode = SetBkMode(thdc,TRANSPARENT);
	holdfont = SelectObject(thdc,fixfont);
	for( y=0,i=0 ; i < 16 ; i++ ) {
		j = LoadString(hinst,1208+i,buff,32);
		SetTextColor(thdc,colortab[idcololst[18+i]]);
		TextOut(thdc,4,y,buff,j);
		if( i == id ) {
			rc.left = 0;
			rc.top = y;
			rc.right = x;
			rc.bottom = y+fixfy1;
			DrawFocusRect(thdc,&rc);
		}
		y += fixfy1;
	}
	SelectObject(thdc,holdfont);
	SetBkMode(thdc,bkmode);
	ReleaseDC(hwnd,thdc);
}

void dispcolo(hwnd)	/* ｶﾗｰ設定画面での見本表示(penvd->colortab[]の色で表示) */
HWND hwnd;
{
	INT32 i,j,k,m,ln,col,y,y0,y1,y2,y3,x,x0,x1,x2,x3,xw,yw,yg,yl,yt;
	HDC thdc;
	RECT rc;
	SHFILEINFOW sfiw;
	HIMAGELIST hil;
	BYTE buff[32];
	HBRUSH hb,hb2,hb4,hb5,hb6,hb7,hbold;
	HPEN holdpen,pss,puu,pgg,pii,pll;
	HFONT holdfont;
	static BYTE exid[12] = { /* ﾋﾞｯﾄ0=1:反転行  ﾋﾞｯﾄ1=1:変更行  ﾋﾞｯﾄ2=1:特殊ﾏｰｸ行 */
		0x00,0x02,0x01,0x03,0x00,0x02,0x00,0x02,0x04,0xff };
	static BYTE excl[12] = { 1,6,1,1,11,13,14,15,1,5 };
	static BYTE *extxt[10] = {/* ここを変更する時はclexntxt[10]も変更要 */
		"通常文字",
		"通常文字:変更行",
		"選択範囲",
		"選択範囲:変更行",
		"コメント",
		"コメント:変更行",
		"#ifdef:奇数",
		"#ifdef:偶数",
		"特殊文字",
		"[EOF]",
		};
	static BYTE *ubtnface[4] = {
		"開く",
		"保存",
		"印刷",
		"UNDO",
		};

	thdc = GetDC(hwnd);
	GetClientRect(hwnd,&rc);
	xw = rc.right;
	yw = rc.bottom;
	yt = gettabheight(0x0000);	/* 多目的ﾊﾞｰ内ﾀﾌﾞの高さ(常にｱｲｺﾝ表示) */
	yg = yt+1+1;			/* yg=多目的ﾊﾞｰの高さ(1行時) */
	y0 = bottony;		/* y0=ﾕｰｻﾞｰ定義ﾊﾞｰの高さ */
	x0 = MINXLISTWIN;	/* x0=ﾘｽﾄｳｨﾝﾄﾞｳの横幅 */
	y1 = gagefy0+GAGEHEIGHT+GAGELINE;	/* y1=桁ｹﾞｰｼﾞの高さ */
	y2 = fixfy1;		/* y2=ﾃｷｽﾄ1行の高さ */
	if( y2 <= fixfy )
		y2 = fixfy+1;
	rc.bottom = y0;
	hb7 = CreateSolidBrush(penvd->colortab[22]);	/* ﾌﾚｰﾑｳｨﾝﾄﾞｳ背景色 */
	FillRect(thdc,&rc,hb7);
/* ﾕｰｻﾞｰ定義ﾊﾞｰを描画 */
	hb = CreateSolidBrush(penvd->colortab[9]);
	for( x=1,i=0 ; i < 4 ; i++ ) {
		dispgenbtn(thdc,hminf,hb,x,0,bottonx,bottony,
			penvd->colortab[21],penvd->colortab[9],COLORBTNBORDER1,COLORBTNBORDER2,ubtnface[i]);
		x += bottonx;
	}
	DeleteObject(hb);
/* ﾘｽﾄｳｨﾝﾄﾞｳを描画 */
	listborder(thdc,1,penvd->colortab[31],0,y0,x0,yw-yg);	/* ﾘｽﾄｳｨﾝﾄﾞｳの境界枠を表示 */
	listwindraw(hwnd,thdc,NULL,0x100100ff,yw-yg);	/* ﾘｽﾄｳｨﾝﾄﾞｳのﾘｽﾄ外の部分を表示 */
	/* ﾘｽﾄ内の上部項目の背景を表示 */
	yl = guideyy+CYCOMBOINTER+COMBOLISTWIN+CYCOMBOINTER;	/* yl=ﾘｽﾄｳｨﾝﾄﾞｳのﾘｽﾄ上側部分の高さ */
	rc.left = 0;
	rc.right = x0-LISTBORDER;
	rc.top = y0+yl+1;
	rc.bottom = rc.top+(lstwincy1*3);
	hb = CreateSolidBrush(penvd->colortab[29]);
	FillRect(thdc,&rc,hb);
	DeleteObject(hb);
	holdpen = SelectObject(thdc,GetStockObject(BLACK_PEN));
	MoveToEx(thdc,rc.left,rc.bottom-1,NULL);
	LineTo(thdc,rc.right,rc.bottom-1);
	MoveToEx(thdc,rc.left,y0+yl,NULL);
	LineTo(thdc,rc.right,y0+yl);
	/* ﾘｽﾄ内の小見出し項目の背景を表示 */
	rc.top = rc.bottom;
	rc.bottom = rc.top+lstwincy1;
	hb = CreateSolidBrush(penvd->colortab[65]);
	FillRect(thdc,&rc,hb);
	DeleteObject(hb);
	/* ﾘｽﾄ内の下部項目の背景を表示 */
	rc.top = rc.bottom;
	rc.bottom = yw-yg-1;
	hb = CreateSolidBrush(penvd->colortab[59]);
	FillRect(thdc,&rc,hb);
	DeleteObject(hb);
	/* ﾘｽﾄ内の選択項目の背景を表示 */
	rc.top = y0+yl+1+(lstwincy1*6);
	rc.bottom = rc.top+lstwincy1;
	hb = CreateSolidBrush(penvd->colortab[61]);
	FillRect(thdc,&rc,hb);
	DeleteObject(hb);
	/* ﾘｽﾄ内の項目文字列(前景)を表示 */
	SetTextColor(thdc,penvd->colortab[46]);
	SetBkMode(thdc,TRANSPARENT);
	holdfont = SelectObject(thdc,hlistf);
	k = ((lstwincy1-listfy)/2);
	for( i=0,y=y0+yl+1 ; i < 10 ; i++,y+=lstwincy1 ) {
		if( i == 3 )
			SetTextColor(thdc,penvd->colortab[66]);
		else if( i == 4 )
			SetTextColor(thdc,penvd->colortab[60]);
		else if( i == 6 )
			SetTextColor(thdc,penvd->colortab[62]);
		else if( i == 7 )
			SetTextColor(thdc,penvd->colortab[60]);
		if( i < 3 ) {
			j = wsprintf(buff," sample%d.txt",i+1);
			if( i == 0 )
				buff[0] = '*';
		}
		else if( i == 3 )
			j = fstrcpy(buff," 小見出し");
		else
			j = wsprintf(buff," filename%d",i-3);
		TextOut(thdc,0,y+k,buff,j);
	}
	SelectObject(thdc,holdfont);
/* 背景を描画 */
	rc.left = x0;
	rc.right = xw;
	rc.top = y0+guideyy+y1;
	rc.bottom = yw-yg;
	editbacksmp(thdc,&rc,penvd->colortab[0]);
/* ｶﾞｲﾄﾞﾗｲﾝを描画 */
	guidesample(thdc,x0,y0,xw);
/* 桁ｹﾞｰｼﾞを描画 */
	rc.left = x0;
	rc.right = x0+(40*fixfx);	/* 40桁分(画面横幅に対して十分大きな桁数) */
	rc.top  = y0+guideyy;
	rc.bottom = y0+guideyy+y1;
	hb2 = CreateSolidBrush(penvd->colortab[43]);
	FillRect(thdc,&rc,hb2);
	pss = CreatePen(PS_SOLID,1,penvd->colortab[25]);
	pgg = CreatePen(PS_SOLID,1,penvd->colortab[44]);
	puu = CreatePen(PS_SOLID,1,penvd->colortab[3]);
	pii = CreatePen(PS_SOLID,1,penvd->colortab[33]);
	SelectObject(thdc,pss);
	ln = (fixfx*WIDNUM);
	for( i = 1 ; i <= GAGELINE ; i++ ) {	/* 桁ｹﾞｰｼﾞ下のﾗｲﾝ */
		MoveToEx(thdc,x0+ln,y0+guideyy+y1-i,NULL);
		LineTo(thdc,xw,y0+guideyy+y1-i);
	}
	rc.left = x0+ln;
	rc.right = rc.left+fixfx;
	rc.top = y0+guideyy+y1;
	rc.top = yw-yg;
	FillSolidRect(thdc,penvd->colortab[39],&rc);	/* ﾌﾞｯｸﾏｰｸ領域の背景色 */
	rc.left = rc.right;
	rc.right += fixfx*OLWIDTH;
	FillSolidRect(thdc,penvd->colortab[67],&rc);	/* アウトラインボタン領域の背景色 */
	holdfont = SelectObject(thdc,hgagef);		/* 桁ｹﾞｰｼﾞ用ﾌｫﾝﾄに切り替え */
	SetTextColor(thdc,penvd->colortab[44]);
	SetBkMode(thdc,TRANSPARENT);
#ifdef MARKCOLUMN
	TextOut(thdc,x0+ln,y0+guideyy+1,BKMARKCHAR,1);
#endif
	y3 = y0+guideyy+y1-GAGELINE;
	SelectObject(thdc,pgg);
	SetBkColor(thdc,penvd->colortab[43]);
	x = x3 = ((WIDNUM+(BMWIDTH+OLWIDTH))*fixfx)+LEFTSPACE;	/* +BMWIDTHはﾌﾞｯｸﾏｰｸ表示桁の分 */
	for( col = 0 ; x < xw ; col++,x+=fixfx ) {
		if( (col%10) == 0 ) {
			MoveToEx(thdc,x0+x,y3-GAGEHEIGHT,NULL);
			LineTo(thdc,x0+x,y3);
			if( col > 0 ) {
				k = wsprintf(buff,"%d",col);
				TextOut(thdc,x0+x-(gagefx*k),y0+guideyy,buff,k);
			}
		}
		else if( (col%5) == 0 ) {
			MoveToEx(thdc,x0+x,y3-(GAGEHEIGHT-2),NULL);
			LineTo(thdc,x0+x,y3);
		}
		else {
			MoveToEx(thdc,x0+x,y3-2,NULL);
			LineTo(thdc,x0+x,y3);
		}
		if( col == 17 ) {		/* ｿﾌﾄﾀﾌﾞﾏｰｸを表示 */
			if( hbitstab1 == NULL )
				hbitstab1 = LoadBitmap(hinst,MAKEINTRESOURCE(MKSOFTTAB1));
			dispbitmarkex(thdc,x0+x,y3-8,fixfx,8,hbitstab1,0,0,penvd->colortab[18],0xff000000);
			SetTextColor(thdc,penvd->colortab[44]);		/* 前景色を戻す */
		}
	}
	PatBlt(thdc,x0+x3+(fixfx*6),y0+guideyy,fixfx,y1-GAGELINE,DSTINVERT);
/* 子ｳｨﾝﾄﾞｳ内の各行を描画 */
	SelectObject(thdc,fixfont);
	k = getfntszid(fixfx,fixfy,&m);
	for( i = 0 ; i < 4 ; i++ ) {
		if( crlfbit[i][k] == NULL )
			crlfbit[i][k] = LoadBitmap(hinst,MAKEINTRESOURCE(MIWIMG11+(i*7)+k));
	}
	hb4 = CreateSolidBrush(penvd->colortab[16]);
	hb5 = CreateSolidBrush(penvd->colortab[32]);
	hb6 = CreateSolidBrush(penvd->colortab[45]);
	for( y=y0+guideyy+y1,i=0 ; y < (yw-yg) ; y += y2,i++ ) {
		rc.left = x0;
		rc.right = x0+(fixfx*WIDNUM);
		rc.top  = y;
		rc.bottom = y+y2;
		if( i >= 10 ) {
			FillRect(thdc,&rc,hb4);
			goto uuuuu;
		}
		wsprintf(buff,"%5d",i+1);	/* WIDNUM 桁表示 */
		if( i == 4 ) {	/* 行番号ｹﾞｰｼﾞの反転表示 */
			gradationrect(thdc,rc.left,rc.top,rc.right,rc.bottom,6,penvd->colortab[17]);
			SetTextColor(thdc,penvd->colortab[16]);
		}
		else {		/* 行番号ｹﾞｰｼﾞの通常表示 */
			FillRect(thdc,&rc,hb4);
			SetTextColor(thdc,penvd->colortab[17]);
		}
		TextOut(thdc,x0,y,buff,WIDNUM);
		if( i == 6 ) {
			rc.left = rc.right;
			rc.right = rc.left+fixfx;
			FillRect(thdc,&rc,hb5);
			SetTextColor(thdc,penvd->colortab[40]);
			TextOut(thdc,rc.left,rc.top,"3",1);
		}
		if( exid[i] == 0xff ) {		/* [EOF]行 */
			rc.left = x0+x3;
			rc.top  = y;
			rc.right = x0+x3+(fixfx*5);
			rc.bottom = y+fixfy;
			FillRect(thdc,&rc,hb6);
			SetTextColor(thdc,penvd->colortab[23]);
			TextOut(thdc,x0+x3,y,extxt[i],(INT32)clexntxt[i]);
			goto uuuuu;
		}
		j = x3+(fixfx*(INT32)clexntxt[i]);	/* 表示した文字列の横幅(ﾋﾟｸｾﾙ) */
		if( exid[i]&0x01 ) {		/* 反転表示行 */
			hb = CreateSolidBrush(penvd->colortab[excl[i]]);
			rc.left = x0+x3;
			rc.top  = y;
			rc.right = x0+j+fixfx;
			rc.bottom = y+fixfy;
			FillRect(thdc,&rc,hb);
			DeleteObject(hb);
			SetTextColor(thdc,penvd->colortab[0]);
			TextOut(thdc,x0+x3,y,extxt[i],(INT32)clexntxt[i]);
			dispbitmarkex(thdc,x0+j,y+m,fixfx,fixfy-m,crlfbit[2][k],0,0,
					penvd->colortab[0],penvd->colortab[(exid[i]&0x02)?7:2]);
		}
		else {				/* 通常表示行 */
			SetTextColor(thdc,penvd->colortab[excl[i]]);
			TextOut(thdc,x0+x3,y,extxt[i],(INT32)clexntxt[i]);
			if( exid[i]&0x04 ) {	/* 特殊ﾏｰｸ明示行 */
				/* ﾊｰﾄﾞﾀﾌﾞ明示 */
				j += fixfx;
				buff[0] = chartab0;
				buff[1] = buff[2] = buff[3] = chartab1;
				SetTextColor(thdc,penvd->colortab[5]);
				TextOut(thdc,x0+j,y,buff,4);
				j += (fixfx*5);
				/* 全角ｽﾍﾟｰｽ */
				buff[0] = sp2char1;
				buff[1] = sp2char2;
				SetTextColor(thdc,penvd->colortab[5]);
				TextOut(thdc,x0+j,y,buff,2);
				j += (fixfx*3);
				/* 制御ｺｰﾄﾞ */
				buff[0] = '^';
				SetTextColor(thdc,penvd->colortab[5]);
				TextOut(thdc,x0+j,y,buff,1);
				buff[0] = 'C';
				SetTextColor(thdc,penvd->colortab[1]);
				TextOut(thdc,x0+j+fixfx,y,buff,1);
				goto uuuuu;
			}
			dispbitmarkex(thdc,x0+j,y+0,fixfx,fixfy-m,crlfbit[2][k],0,0,
					penvd->colortab[(exid[i]&0x02)?7:2],0xff000000);	/* 背景透過で描画 */
		}
		uuuuu:
		SelectObject(thdc,pii);			/* 背景横罫線 */
		MoveToEx(thdc,x0,y+fixfy,NULL);
		LineTo(thdc,x0+ln,y+fixfy);
		MoveToEx(thdc,x0+ln+fixfx*(BMWIDTH+OLWIDTH),y+fixfy,NULL);
		LineTo(thdc,xw,y+fixfy);
		if( i == 4 ) {
			SelectObject(thdc,puu);			/* ｶｰｿﾙ行ｱﾝﾀﾞｰﾗｲﾝ */
			MoveToEx(thdc,x0+ln+fixfx*(BMWIDTH+OLWIDTH),y+fixfy,NULL);
			LineTo(thdc,xw,y+fixfy);
		}

		if (i < 10) {
			/* アウトラインボタン */
			drawcollapsesamplebutton(thdc,x0+ln+fixfx*BMWIDTH,y,fixfx,y2,
				  ((i == 0 || i == 4) ? 0x00000001 : 0) /* ボタン */
				| ((i != 0 && i != 9) ? 0x00000002 : 0) /* 水平ライン */
				| ((i == 9)           ? 0x00000004 : 0) /* 終端ライン */);
		}
	}
/* 多目的ﾊﾞｰを表示 */
	gradationrect(thdc,0,yw-yg,xw,yw,2|0x0100,penvd->colortab[22]);
	x = LEFTTABCX1;
	y = yw-yg+1;
	dispgenbtn(thdc,NULL,NULL,0,y,LEFTBTNCX,yt,
		penvd->colortab[20],0xfe000000|penvd->colortab[19],COLORBTNBORDER1,COLORBTNBORDER2,"\x02");
	dispgenbtn(thdc,NULL,NULL,LEFTBTNCX,y,LEFTBTNCX,yt,
		penvd->colortab[20],0xfe000000|penvd->colortab[19],COLORBTNBORDER1,COLORBTNBORDER2,"\x03");
	pll = CreatePen(PS_SOLID,1,penvd->colortab[48]);	/* 多目的ﾊﾞｰﾀﾌﾞ線色 */
	SelectObject(thdc,hbalf);
	SelectObject(thdc,pll);
	hbold = SelectObject(thdc,GetStockObject(NULL_BRUSH));	/* NULL_BRUSH=背景透過 */
	SetBkMode(thdc,TRANSPARENT);
	y3 = y+1+((yt-2-balfy)/2);
	k = fstrcpy(buff,"sample1.txt");
	xw = getvtabwidsmp(&x1,&x2);
	FillMemory(&sfiw,sizeof(sfiw),0);
	hil = (HIMAGELIST)SHGetFileInfoW(L".TXT",FILE_ATTRIBUTE_NORMAL,&sfiw,sizeof(sfiw),
			SHGFI_USEFILEATTRIBUTES|SHGFI_SMALLICON|SHGFI_SYSICONINDEX);
	for( i = 0 ; i < 4 ; i++ ) {
		gradationrect(thdc,x+1,y+1,x+xw-2,y+yt-1,4,(i==0)?penvd->colortab[0]:penvd->colortab[19]);
		RoundRect(thdc,x,y,x+xw-1,y+yt,4,4);	/* ﾀﾌﾞの枠を描画 */
		buff[6] = '1'+i;
		if( hil )
			ImageList_Draw(hil,sfiw.iIcon,thdc,x+3,y+(LOWADD/2),ILD_NORMAL|ILD_TRANSPARENT);
		if( i < 2 ) {
			SetTextColor(thdc,penvd->colortab[49]);
			TextOut(thdc,x+x1-2-balfx,y3,"*",1);
		}
		SetTextColor(thdc,(i==0)?penvd->colortab[1]:penvd->colortab[20]);
		TextOut(thdc,x+x1,y3,buff,k);
		if( i == 0 ) {		/* ｶﾚﾝﾄﾌｧｲﾙﾀﾌﾞ中の閉じる「×」ﾎﾞﾀﾝの表示 */
			/* ﾎﾞﾀﾝの高さは13ﾋﾟｸｾﾙだが、上部の隙間の計算はﾎﾞﾀﾝの高さを14ﾋﾟｸｾﾙと見なして行なう */
			dispgenbtn(thdc,NULL,NULL,x+x2,y+1+((yt-2-14)/2),14,13,
				COLORCLOSEBTNFOR,COLORCLOSEBTNBAK,COLORBTNBORDER3,COLORBTNBORDER3,"\x0a");
		}
		x += xw;
	}
	SelectObject(thdc,hbold);
/* ﾘｿｰｽを戻す */
	SelectObject(thdc,holdfont);
	SelectObject(thdc,holdpen);
	DeleteObject(pss);
	DeleteObject(pgg);
	DeleteObject(puu);
	DeleteObject(pii);
	DeleteObject(pll);
	DeleteObject(hb2);
	DeleteObject(hb4);
	DeleteObject(hb5);
	DeleteObject(hb6);
	DeleteObject(hb7);
	ReleaseDC(hwnd,thdc);
}

INT32 pos2colid(hwnd,x,y)	/* ｶﾗｰ見本上の指定位置のｶﾗｰIDを調べる */
HWND hwnd;	/* ｶﾗｰ見本ｳｨﾝﾄﾞｳ */
INT32 x;
INT32 y;
{
	INT32 i,j,k,l,m,n,x0,y0,x1,y1,x2,y2,x3,x4,yt;
	RECT rc;

	y0 = bottony;
	x0 = MINXLISTWIN;
	x1 = LEFTTABCX1;
	x3 = ((WIDNUM+BMWIDTH+OLWIDTH)*fixfx)+LEFTSPACE;
	GetClientRect(hwnd,&rc);
	yt = gettabheight(0x0000);		/* 多目的ﾊﾞｰ上のﾀﾌﾞの高さ(常にｱｲｺﾝ表示) */
	y1 = rc.bottom-rc.top-(yt+1+1);		/* yt+1+1=多目的ﾊﾞｰの高さ  yt+1=多目的ﾊﾞｰ内のﾎﾞﾀﾝの高さ */
	j = (y0+guideyy+gagefy0+GAGEHEIGHT+GAGELINE);
	y2 = (y0+guideyy+CYCOMBOINTER+COMBOLISTWIN);
	k = fixfy1;
	if( k <= fixfy )
		k = fixfy+1;
	if( x < rc.left || x >= rc.right || y < rc.top || y >= rc.bottom )
		return(-1);
	if( y < y0 ) {		/* ﾕｰｻﾞｰ定義ﾊﾞｰ */
		for( l = 0 ; l < 4 ; l++ ) {
			if( x < (1+(bottonx*l)+4+(minfx*2)) ) {
				i = 9;	/* ﾕｰｻﾞｰ定義ﾊﾞｰﾎﾞﾀﾝ背景色 */
				break;
			}
			else if( x < (1+(bottonx*l)+4+(minfx*6)) ) {
				i = 21;	/* ﾕｰｻﾞｰ定義ﾊﾞｰﾎﾞﾀﾝ文字色 */
				break;
			}
			else if( x < (1+(bottonx*l)+bottonx) ) {
				i = 9;	/* ﾕｰｻﾞｰ定義ﾊﾞｰﾎﾞﾀﾝ背景色 */
				break;
			}
		}
		if( l >= 4 )
			return(22);	/* ﾌﾚｰﾑｳｨﾝﾄﾞｳ背景色 */
	}
	else if( y >= y1 ) {		/* 多目的ﾊﾞｰ */
		if( x < (LEFTBTNCX+LEFTBTNCX) )
			i = 19;		/* 多目的ﾊﾞｰ背景色 */
		else if( x < x1 )
			return(22);	/* ﾌﾚｰﾑｳｨﾝﾄﾞｳ背景色 */
		else {
			n = getvtabwidsmp(&x2,&x4);
			l = ((x-x1)/n);
			m = ((x-x1)%n);
			if( m == 0 || m >= (n-2) )	/* ﾀﾌﾞの左端または右端 */
				i = 48;			/* 多目的ﾊﾞｰ上のﾀﾌﾞ境界線色 */
			else if( m < (x2-4-balfx) )	/* ｱｲｺﾝ上 */
				return(-1);
			else if( m < x2 ) {		/* 変更ﾏｰｸ上 */
				if( l < 2 )
					i = 49;		/* 多目的ﾊﾞｰ上の変更ﾏｰｸ色 */
				else
					i = 19;		/* 多目的ﾊﾞｰ上のﾀﾌﾞ内背景色 */
			}
			else if( m < x4 ) {		/* ﾌｧｲﾙ名上 */
				if( l == 0 )		/* ｶﾚﾝﾄﾌｧｲﾙのﾀﾌﾞ */
					i = 1;		/* 通常文字色 */
				else			/* 開いているﾀﾌﾞ */
					i = 20;		/* 多目的ﾊﾞｰ上のﾀﾌﾞ内文字色 */
			}
			else {				/* 「×」ﾏｰｸ上 */
				if( l == 0 )
					return(-1);
				else
					i = 19;		/* 多目的ﾊﾞｰ上のﾀﾌﾞ内背景色 */
			}
		}
	}
	else if( x < x0 ) {		/* ﾘｽﾄｳｨﾝﾄﾞｳ上 */
		if( x >= (x0-LISTBORDER) )
			i = 31;		/* ﾘｽﾄｳｨﾝﾄﾞｳ上ﾘｽﾄ外背景色 */
		else if( y < (y0+guideyy) ) {	/* ﾀｲﾄﾙﾊﾞｰ上 */
			if( x >= (x0-LISTBORDER-lstwindefcx) )			/* 「X」ﾎﾞﾀﾝ上 */
				return(-1);
			else if( x >= (x0-LISTBORDER-lstwindefcx-lstwindefcx) )	/* 「▼」ﾎﾞﾀﾝ上 */
				return(-1);
			else
				return(-1);
		}
		else if( y < (y0+guideyy+CYCOMBOINTER) ) {	/* ﾀｲﾄﾙﾊﾞｰと上側ｺﾝﾎﾞﾎﾞｯｸｽの間 */
			i = 31;		/* ﾘｽﾄｳｨﾝﾄﾞｳ上ﾘｽﾄ外背景色 */
		}
		else if( y < y2 ) {		/* 上側ｺﾝﾎﾞﾎﾞｯｸｽ上 */
			l = x0-LISTBORDER;
			if( x >= (l-lstwindefcx) && x < l )	/* ｺﾝﾎﾞﾎﾞｯｸｽ内のﾌﾟﾙﾀﾞｳﾝﾎﾞﾀﾝ */
				i = 63;		/* ﾘｽﾄｳｨﾝﾄﾞｳ上ﾎﾞﾀﾝ背景色 */
			else
				return(-1);
		}
		else if( y < (y2+CYCOMBOINTER) ) {	/* 上側ｺﾝﾎﾞﾎﾞｯｸｽとﾘｽﾄの間 */
			i = 31;		/* ﾘｽﾄｳｨﾝﾄﾞｳ上ﾘｽﾄ外背景色 */
		}
		else {				/* ﾘｽﾄﾎﾞｯｸｽ上 */
			y -= (y2+CYCOMBOINTER+1);	/* +1は上側の境界線 */
			if( y < (lstwincy1*3) ) {	/* 上部項目 */
				if( x < (listfx*12) ) {
					if( y >= lstwincy1 && x < listfx )	/* 2～3行目の1桁目 */
						i = 29;		/* ﾘｽﾄｳｨﾝﾄﾞｳ上部背景色 */
					else
						i = 46;		/* ﾘｽﾄｳｨﾝﾄﾞｳ上部文字色 */
				}
				else
					i = 29;		/* ﾘｽﾄｳｨﾝﾄﾞｳ上部背景色 */
			}
			else if( y < (lstwincy1*4) ) {	/* 小見出し項目 */
				if( x < (listfx*9) )
					i = 66;
				else
					i = 65;
			}
			else if( y < (lstwincy1*6) ) {	/* 通常項目 */
				if( x < (listfx*10) )
					i = 60;
				else
					i = 59;
			}
			else if( y < (lstwincy1*7) ) {	/* 選択項目 */
				if( x < (listfx*10) )
					i = 62;
				else
					i = 61;
			}
			else if( y < (lstwincy1*10) ) {	/* 通常項目 */
				if( x < (listfx*10) )
					i = 60;
				else
					i = 59;
			}
			else				/* 空行 */
				i = 59;
		}
	}
	else if( y < (y0+guideyy) ) {	/* ｶﾞｲﾄﾞﾗｲﾝ */
		x -= x0;
		n = ((xmodesz1-(guidex*8))/2);
		if( x < (8+(guidex*7)) )
			i = 4;	/* ｶﾞｲﾄﾞﾗｲﾝ背景色 */
		else if( x < (8+(guidex*10)) )
			i = 8;	/* ｶﾞｲﾄﾞﾗｲﾝ文字色 */
		else if( x < (8+(guidex*13)) )
			i = 4;	/* ｶﾞｲﾄﾞﾗｲﾝ背景色 */
		else if( x < (8+(guidex*16)) )
			i = 8;	/* ｶﾞｲﾄﾞﾗｲﾝ文字色 */
		else if( x < (8+(guidex*16)+4) )
			i = 34;	/* ｶﾞｲﾄﾞﾗｲﾝ上の線の色 */
		else if( x < (8+(guidex*16)+16) )
			i = 4;	/* ｶﾞｲﾄﾞﾗｲﾝ背景色 */
		else if( x < (8+(guidex*16)+16+n) )
			i = 36;	/* ｶﾞｲﾄﾞﾗｲﾝﾎﾞﾀﾝ背景色 */
		else if( x < (8+(guidex*16)+16+n+(guidex*8)) )
			i = 37;	/* ｶﾞｲﾄﾞﾗｲﾝﾎﾞﾀﾝ文字色 */
		else if( x < (8+(guidex*16)+16+xmodesz1) )
			i = 36;	/* ｶﾞｲﾄﾞﾗｲﾝﾎﾞﾀﾝ背景色 */
		else
			i = 4;	/* ｶﾞｲﾄﾞﾗｲﾝ背景色 */
	}
	else if( y < (j-2) ) {	/* 桁ｹﾞｰｼﾞ上 */
		x -= x0;
		if( x >= (x3+(fixfx*17)) && x < (x3+(fixfx*18)) )
			i = 18;	/* 桁ｹﾞｰｼﾞ上の各種ﾏｰｸ */
#ifdef MARKCOLUMN
		else if( x < (x3-fixfx) )
			i = 43;
		else if( x < x3 )
			i = 44;
#else
		else if( x < x3 )
			i = 43;
#endif
		else if( x < (x3+(fixfx*10)-(gagefx*2)) )
			i = 43;		/* 桁ｹﾞｰｼﾞ背景色 */
		else if( x < (x3+(fixfx*10)) )
			i = 44;		/* 桁ｹﾞｰｼﾞ文字色 */
		else if( x < (x3+(fixfx*20)-(gagefx*2)) )
			i = 43;		/* 桁ｹﾞｰｼﾞ背景色 */
		else if( x < (x3+(fixfx*20)) )
			i = 44;		/* 桁ｹﾞｰｼﾞ文字色 */
		else
			i = 43;		/* 桁ｹﾞｰｼﾞ背景色 */
	}
	else if( y < j ) {	/* 桁ｹﾞｰｼﾞ下の境界線上 */
		i = 25;
	}
	else {			/* 編集ﾃｷｽﾄ表示上 */
		x -= x0;
		for( l = 1 ; y >= (j+(k*l)) ; l++ ) ;
		l--;
		if( y >= (j+(k*(l+1))-3) ) {
			if( l == 4 && x >= (x3-OLWIDTH*fixfx-LEFTSPACE) )
				i = 3;		/* ｱﾝﾀﾞｰﾗｲﾝ色 */
			else if( x >= (fixfx*WIDNUM) && x < (x3-OLWIDTH*fixfx-LEFTSPACE) )
				goto bookmk;
			else if( x >= (fixfx*WIDNUM) && x < (x3-LEFTSPACE) )
				goto outline;
			else
				i = 33;		/* 背景罫線色 */
		}
		else if( x < (fixfx*WIDNUM) ) {		/* 行ｹﾞｰｼﾞ */
			if( y < (j+(k*9)) ) {	/* 1～9行 */
				if( y >= (j+(k*4)) && y < (j+(k*5)) )	/* 5行 */
					i = 17;
				else if( x < (fixfx*(WIDNUM-1)) )	/* 行ｹﾞｰｼﾞ背景 */
					i = 16;
				else					/* 行ｹﾞｰｼﾞ文字 */
					i = 17;
			}
			else if( y < (j+(k*10)) ) {	/* 10行 */
				if( x < (fixfx*(WIDNUM-2)) )	/* 行ｹﾞｰｼﾞ背景 */
					i = 16;
				else				/* 行ｹﾞｰｼﾞ文字 */
					i = 17;
			}
			else {
				i = 16;
			}
		}
		else if( x < (x3-OLWIDTH*fixfx-LEFTSPACE) ) {		/* ﾌﾞｯｸﾏｰｸ領域 */
			bookmk:
			if( y >= (j+(k*6)) && y < (j+(k*7)) ) /* 7行目はﾌﾞｯｸﾏｰｸ表示背景色 */
				i = 32;
			else			/* ﾌﾞｯｸﾏｰｸ領域背景色 */
				i = 39;
		}
		else if( x < (x3-LEFTSPACE) ) {		/* アウトラインボタン領域 */
			outline:
			i = 67;
		}
		else if( x < x3 ) {		/* ﾌﾞｯｸﾏｰｸ表示桁の右隣の空白域 */
			i = 0;		/* 通常ｳｨﾝﾄﾞｳ背景色 */
		}
		else if( l == 0 ) {	/* 通常ﾃｷｽﾄ */
			i = 1;
			goto lllll;
		}
		else if( l == 1 ) {	/* 通常ﾃｷｽﾄ(変更行) */
			i = 6;
			goto lllll;
		}
		else if( l == 2 ) {	/* 選択範囲 */
			i = 1;
			goto lllll;
		}
		else if( l == 3 ) {	/* 選択範囲(変更行) */
			i = 6;
			goto lllll;
		}
		else if( l == 4 ) {	/* ｺﾒﾝﾄ明示 */
			if( y < (j+(k*(l+1))-3) ) {
				i = COLORCOMT;
				goto lllll;
			}
			else
				i = 3;	/* ｱﾝﾀﾞｰﾗｲﾝ */
		}
		else if( l == 5 ) {	/* ｺﾒﾝﾄ明示(変更行) */
			i = COLORCOMTU;
			goto lllll;
		}
		else if( l == 6 ) {	/* C/C++言語#ifdefﾌﾞﾛｯｸ明示 */
			i = COLORIFDEF;
			goto lllll;
		}
		else if( l == 7 ) {	/* C言語#ifdefﾌﾞﾛｯｸ明示(変更行) */
			i = COLORIFDEFU;
			lllll:
			m = x3+(fixfx*(INT32)clexntxt[l]);
			if( x >= m ) {
				if( x < (m+fixfx) ) {	/* 改行文字の位置 */
					if( l&0x01 )	/* 変更行 */
						i = 7;
					else		/* 通常行 */
						i = 2;
				}
				else
					i = 0;		/* 通常ｳｨﾝﾄﾞｳ背景色 */
			}
		}
		else if( l == 8 ) {	/* 特殊文字表示 */
			i = 5;
		}
		else if( l == 9 ) {	/* [EOF]行 */
			if( x < (x3+(fixfx*(INT32)clexntxt[9])) )
				i = 45;		/* [EOF]ﾏｰｸ背景色 */
			else
				i = 0;		/* 通常ｳｨﾝﾄﾞｳ背景色 */
		}
		else
			i = 0;
	}
	return(i);
}

void startstop(hwnd,id,ml)	/* 処理中止ｳｨﾝﾄﾞｳの表示 */
HWND hwnd;	/* 親ｳｨﾝﾄﾞｳ */
INT32 id;	/* 中止ﾀｲﾌﾟ */
INT32 ml;	/* id=98(ｸﾞﾛｰﾊﾞﾙ検索)の時→条件表示行数 	*/
		/* id<0の時→ｳｨﾝﾄﾞｳﾀｲﾄﾙはgetpartstr(0-id,ml,,)	*/
{
	INT32 x0,y0,xw,yw;
	DWORD style;
	HMENU hm;
#ifdef STOPDLGPOPUP
	RECT rc;
#endif
	BYTE buff[64];

	if( id == 0 )
		fstrcpy(buff,ppmac->strbuffx);
	else {
		if( endstop() )		/* すでに「中止」ｳｨﾝﾄﾞｳを表示中 --- あり得ないが */
			mipaint();
		if( id < 0 )
			getpartstr(0-id,ml,buff,62);
		else
			LoadString(hinst,id,buff,62);	/* ﾀｲﾄﾙﾊﾞｰﾒｯｾｰｼﾞの取得 */
	}
	if( id == 99 ) {			/* ﾌｧｲﾙの検索 */
		style = MIS_STOPDLG4;
		x0 = sysx1*17;
		xw = sysx1*24;
		yw = sysy1*6;
	}
	else if( id == 98 ) { 			/* ｸﾞﾛｰﾊﾞﾙ検索(grep) */
		style = MIS_STOPDLG5;
		x0 = fixfx*17;
		xw = sysx1*70;
		yw = sysy1*((ml*2)/3+8);
	}
	else if( id == 395 || id == 396 || id < 0 ) {	/* C関数定義の検索/見出し行の検索/CSV全行処理/Etc */
		style = MIS_STOPDLG4;
		x0 = fixfx*17;
		xw = (sysx1*((id<0)?30:50));
		yw = sysy1*6;
	}
	else if( id == 0 ) {			/* ﾏｸﾛ言語のstopon()関数 */
		style = MIS_STOPDLG3;
		x0 = fixfx*17;
		xw = sysx1*48;
		yw = sysy1*6;
	}
	else if( id == 23 ) {			/* 確認なし置換 */
		style = MIS_STOPDLG2;
		x0 = (fixfx*10)+8;
		xw = sysx1*24;
		yw = sysy1*6;
	}
	else {				/* 一般の「中止」ﾀﾞｲｱﾛｸﾞ */
		/* 76=ｷｰﾎﾞｰﾄﾞﾏｸﾛの指定回数実行		*/
		/* 77=等差数字列の指定回数挿入		*/
		/* 97=対応括弧の検索			*/
		/* 1306=ﾌｧｲﾙ比較(diff)			*/
		/*   (1424,0)=ｼﾞｬﾝﾌﾟ中、(1424,1)=検索中、(1424,2)=切り取り/ｺﾋﾟｰ中、(1424,3)=貼り付け中 */
		style = (WS_CHILD|MIS_STOPDLG1);
		x0 = (fixfx*10)+8;
		xw = sysx1*24;
		yw = (sysy1*2)+20;
	}
	y0 = 0;
	if( hwnd == NULL ) {		/* 親ｳｨﾝﾄﾞｳの指定がない場合 */
		if( ap )
			hwnd = ap->hwnd;
		else if( hmdiwnd )
			hwnd = hmdiwnd;
		else if( hfwnd )
			hwnd = hfwnd;
		else if( hwndlstwin )	/* SDIﾓｰﾄﾞでのﾘｽﾄｳｨﾝﾄﾞｳ専用ﾌﾟﾛｾｽの場合のみ */
			hwnd = hwndlstwin;
		else			/* ﾊﾞｯｸｸﾞﾗｳﾝﾄﾞでのｸﾞﾛｰﾊﾞﾙ検索時 */
			hwnd = NULL;	/* ﾃﾞｽｸﾄｯﾌﾟｳｨﾝﾄﾞｳ */
	}
#ifdef STOPDLGPOPUP
	style |= (WS_POPUP|WS_CAPTION|WS_BORDER|WS_VISIBLE|WS_CLIPCHILDREN);
	hm = NULL;
	GetWindowRect(hwnd,&rc);
	x0 += rc.left;
	y0 += rc.top;
	if( hwnd == hwndlstwin ) {	/* 親ｳｨﾝﾄﾞｳがﾘｽﾄｳｨﾝﾄﾞｳの場合、ﾘｽﾄｳｨﾝﾄﾞｳがｽｸﾘｰﾝの端にある場合を考慮 */
		if( xw00 == 0 )
			holescreen();
		if( (x0+xw) > (x000+xw00) )
			x0 = x000+xw00-xw;
		if( (y0+yw) > (y000+yw00) )
			y0 = y000+yw00-yw;
	}
	else
		hwnd = hfwnd;
#else
	style |= (WS_CHILD|WS_CAPTION|WS_BORDER|WS_VISIBLE|WS_CLIPCHILDREN);
	hm = (HMENU)2000;
	if( ap && ap->hwnd == hwnd ) {	/* 編集子ｳｨﾝﾄﾞｳを親ｳｨﾝﾄﾞｳとする場合 */
		style |= WS_CLIPSIBLINGS;	/* ｽｸﾛｰﾙﾊﾞｰ(兄弟ｳｨﾝﾄﾞｳ)の下に隠れるように設定 */
		if( (x0+xw) > ap->xclient )
			x0 = 0;
	}
#endif
	if( (winhwnd=CreateWindowEx(0,miclasa,buff,style,x0,y0,xw,yw,hwnd,hm,hinst,NULL)) ) {
#ifdef STOPDLGPOPUP
		SetFocus(winhwnd);
#else
		EnableWindow(winhwnd,TRUE);
		SetCapture(stophwnd);
		SetFocus(stophwnd);
#endif
		UpdateWindow(winhwnd);
		winflgx = winflgstop = 0;
		winflgcount++;
	}
	else {
		winflg = winflgstop = winflgx = 0;
	}
}

INT32 endstop()			/* 「中止」ﾀﾞｲｱﾛｸﾞを消去する */
{
	if( ( winflg > 0 && winflg < 10 ) && winhwnd ) {	/* 「中止」ﾀﾞｲｱﾛｸﾞ表示中 */
		ReleaseCapture();
#ifdef STOPDLGPOPUP
		if( hwndlstwin && (LSTWINSTAT&0x0007) == 0x0000 && (LSTWINSTAT&0x0030) != 0x0000 )	/* 通常ﾎﾟｯﾌﾟｱｯﾌﾟのﾘｽﾄｳｨﾝﾄﾞｳ */
			EnableWindow(hwndlstwin,TRUE);
#ifdef SDILISTWIN
		EnableWindow(hfwnd?hfwnd:sdilisthwnd,TRUE);
#else
		EnableWindow(hfwnd,TRUE);
#endif
		if( sssmode&SYS_UNIQ ) {	/* SDIﾓｰﾄﾞ */
			if( hfwnd && ap )
				SetFocus(ap->hwnd);
		}
#endif
		DestroyWindow(winhwnd);
		winhwnd = NULL;
		stophwnd = NULL;
		sccchwnd = NULL;
		sttthwnd = NULL;
		gsddd = NULL;
		winflg = winflgstop = 0;
		if( winflgx ) {
			if( hfwnd )
				PostMessage(hfwnd,WM_USER+188+winflgx,sdibrkwp,sdibrklp);
			winflgx = 0;
		}
		if( winflgcount > 0 ) {
			if( sssmode&SYS_UNIQ )	/* SDIﾓｰﾄﾞ */
				winflgcount--;
			else			/* MDIﾓｰﾄﾞ */
				winflgcount = 0;
		}
		return(1);
	}
	else {
		winflg = winflgstop = winflgx = 0;
		return(0);
	}
}

INT32 stopchk()		/*「中止」ﾀﾞｲｱﾛｸﾞ表示時のﾒｯｾｰｼﾞ処理(0=中止なし  1=中止した) */
{
	MSG msg;

	if( winflg > 0 && winflg < 10 ) {	/* 「中止」ﾀﾞｲｱﾛｸﾞを表示中 */
		for( ; ; ) {
			if( PeekMessage(&msg,NULL,0,0,PM_NOYIELD|PM_REMOVE) ) {
				if( stopchkmess(&msg) )
					return(1);
			}
			else			/* ﾒｯｾｰｼﾞｷｭｰにﾒｯｾｰｼﾞがない */
				return(0);
		}
		return(0);
	}
	else
		return(0);
}

INT32 stopchkmess(pmsg)		/* 「中止」ﾀﾞｲｱﾛｸﾞ表示時のﾒｯｾｰｼﾞ処理(0=中止なし  1=中止した) */
MSG *pmsg;
{
	INT32 x,y;
	struct ETEXT *tp;

	if( pmsg->message >= WM_MOUSEFIRST && pmsg->message <= WM_MOUSELAST ) {
		if( pmsg->hwnd == stophwnd && pmsg->message == WM_LBUTTONDOWN ) {
			y = (SHORT)(HIWORD(pmsg->lParam));
			x = (SHORT)(LOWORD(pmsg->lParam));
			if( y >= 0 && y < (sysy1+sysy1) && x >= 0 && x < (sysx1*14) )
				return(1);
		}
#ifdef STOPDLGPOPUP
		if( winhwnd ) {		/* 実際に「中止」ﾀﾞｲｱﾛｸﾞが表示されている */
			tp = mp;
			DispatchMessage(pmsg);
			setmp(tp);
		}
#endif
	}
	else if( pmsg->message >= WM_KEYFIRST && pmsg->message <= WM_KEYLAST ) {
		if( pmsg->message == WM_KEYDOWN ) {
			if( pmsg->wParam == VK_ESCAPE || pmsg->wParam == VK_PAUSE )	/* Esc または Pause で中止 */
				return(1);
		}
	}
	else if( pmsg->message == WM_COMMAND ) {
	}
	else if( pmsg->message == (WM_USER+189) ) {
		winflgx = 1;
		sdibrkwp = sdibrklp = 0;
	}
	else if( pmsg->message == (WM_USER+190) ) {
		winflgx = 2;
		sdibrkwp = pmsg->wParam;
		sdibrklp = pmsg->lParam;
	}
	else {
		if( winhwnd ) {		/* 実際に「中止」ﾀﾞｲｱﾛｸﾞが表示されている */
			tp = mp;
			DispatchMessage(pmsg);
			setmp(tp);
		}
	}
	return(0);
}

INT32 stopchkm(flag)	/* 処理中止のための Pauseｷｰ/Escｷｰ のﾁｪｯｸ */
INT32 flag;	/* 0=Pauseｷｰのみﾁｪｯｸ  1=PauseｷｰとEscｷｰをﾁｪｯｸ */
{
	MSG msg;

	if( PeekMessage(&msg,NULL,WM_KEYFIRST,WM_KEYLAST,PM_NOYIELD|PM_NOREMOVE) ) {
		if( msg.message == WM_KEYDOWN ) {
			if( msg.wParam == VK_PAUSE || ( msg.wParam == VK_ESCAPE && flag ) ) {
				PeekMessage(&msg,NULL,WM_KEYFIRST,WM_KEYLAST,PM_NOYIELD|PM_REMOVE);
				return(1);
			}
		}
		if( msg.message != WM_CHAR )
			PeekMessage(&msg,NULL,WM_KEYFIRST,WM_KEYLAST,PM_NOYIELD|PM_REMOVE);
	}
	return(0);
}

INT32 mesflush(flag)	/* 処理中止のための Pauseｷｰ/Escｷｰ のﾁｪｯｸ(すべてのﾒｯｾｰｼﾞをｷｭｰから取り除く) */
INT32 flag;	/* 0=その他ﾒｯｾｰｼﾞも無視   1=その他ﾒｯｾｰｼﾞはDispatchMessage()	*/
{
	INT32 stop;
	struct ETEXT *tp;
	MSG msg;

	for( stop = 0 ; ; ) {
		if( PeekMessage(&msg,NULL,0,0,PM_NOYIELD|PM_REMOVE) ) {
			if( msg.message >= WM_MOUSEFIRST && msg.message <= WM_MOUSELAST )
				continue;
			else if( msg.message >= WM_KEYFIRST && msg.message <= WM_KEYLAST ) {
				if( msg.message == WM_KEYDOWN ) {
					if( msg.wParam == VK_PAUSE || msg.wParam == VK_ESCAPE )
						stop = 1;
				}
				continue;
			}
			else if( msg.message == WM_COMMAND )
				continue;
			else {			/* その他のﾒｯｾｰｼﾞ */
				if( flag ) {
					tp = mp;
					DispatchMessage(&msg);
					setmp(tp);
				}
			}
		}
		else		/* ﾒｯｾｰｼﾞｷｭｰにﾒｯｾｰｼﾞがない */
			break;
	}
	return(stop);
}

void keyflush()		/* ｷｰﾌﾗｯｼｭ */
{
	MSG msg;

	for( ; ; ) {
		if( !PeekMessage(&msg,NULL,WM_KEYFIRST,WM_KEYLAST,PM_NOYIELD|PM_REMOVE) )
			break;
	}
}

/* 機能名文字列を得る(関数値には吹き出し文字列のﾊﾞｲﾄ数を返す) */
INT32 getfuncstr(id,flag,pshort,plong,libhead)
INT32 id;	/* 機能番号 id */
INT32 flag;	/* ﾋﾞｯﾄ0:  0=単純に機能を表す文字列を返す 			*/
		/*         1=現在の状態を考慮した文字列を返す 			*/
		/* ﾋﾞｯﾄ4:  0=詳細説明(*plong)の最後に機能番号表記なし 		*/
		/*         1=詳細説明(*plong)の最後に機能番号表記を加える	*/
		/* ﾋﾞｯﾄ8:  0=機能番号600～624においてｶﾚﾝﾄﾌｧｲﾙを考慮しない	*/
		/*         1=機能番号600～624においてｶﾚﾝﾄﾌｧｲﾙを考慮する		*/
BYTE *pshort;	/* 吹き出し文字列(最大48ﾊﾞｲﾄ)  ---- 短い機能名			*/
		/*   (実際の吹き出し文字列は PATHSIZE+128 ﾊﾞｲﾄまで可能)		*/
BYTE *plong;	/* 詳細説明文字列(最大128ﾊﾞｲﾄ) ---- 長い機能名			*/
		/*   (実際の詳細説明文字列は PATHSIZE+128 ﾊﾞｲﾄまで可能)		*/
BYTE *libhead;	/* ﾗｲﾌﾞﾗﾘのﾍｯﾀﾞｰ部分のﾃﾞｰﾀ(先頭5ﾌﾞﾛｯｸ)へのﾎﾟｲﾝﾀ 		*/
{
	INT32 i,j,k;
	BYTE *p,fmtstr[80],libbuff[4096*5];

	regen:
	k = 0;		/* 吹き出し文字列のﾊﾞｲﾄ数をｸﾘｱ */
	if( id < 0 ) {			/* 機能が定義できない場合 */
		if( pshort )
			LoadString(hinst,699,pshort,48);
		if( plong )
			LoadString(hinst,699,plong,128);
		return(k);
	}
	else if( id < 256 ) {		/* 一般機能番号(0～255) */
		if( pshort ) {
			if( id == ID_KMACDEF && (flag&0x0001) )
				i = 1030+((kmacexe==1)?1:0);
			else if( id == ID_INSOVW && (flag&0x0001) )
				i = 1032+insovl;
			else
				i = STRIDFNC1+id;
			k = LoadString(hinst,i,pshort,48);
			if( flag&0x0001 ) {	/* 現在の状態を考慮した文字列を返す */
				if( id == ID_KEICHG )
					k += getpartstr(292,keimode,pshort+k,32);
				else if( id == ID_KMACEXE ) {
					if( ppmac->kmacbuf[0] ) {
						*(pshort+(k++)) = 0x0d;
						if( ppmac->kmacdsc[0] )
							k += fstrcpy(pshort+k,ppmac->kmacdsc);
						else
							k += getpartstr(1395,0,pshort+k,48);
					}
				}
				else if( id == ID_EXECRMAC ) {
					if( crrnam[0] ) {
						*(pshort+(k++)) = 0x0d;
						k += fstrcpy(pshort+k,crrnam);
						*(pshort+(k++)) = ' ';
						*(pshort+(k++)) = ' ';
						k += fstrcpy(pshort+k,crrcomm);
					}
				}
			}
		}
		if( plong ) {
			if( id == ID_SPASTE && (flag&0x0001) ) {
				if( ap && ap->bin2mode )
					LoadString(hinst,1465,plong,128);
#ifdef SELMODENEW
				else if( ap && ap->selflg )
#else
				else if( selflg )
#endif
					LoadString(hinst,968,plong,128);
				else
					goto nnnfunc1;
			}
			else if( id == ID_EXECRMAC && (flag&0x0001) ) {
				if( crrnam[0] == '\0' )
					goto nnnfunc1;
				p = plong;
				p += LoadString(hinst,STRIDFNC1+id,p,48);
				*p++ = '(';
				*p++ = ' ';
				p += fstrcpy(p,crrnam);
				*p++ = ' ';
				*p++ = ' ';
				p += fstrcpy(p,crrcomm);
				*p++ = ' ';
				*p++ = ')';
				goto nnnfunc2;
			}
			else {
				nnnfunc1:
				p = plong;
				p += LoadString(hinst,STRIDFNC2+id,p,128);
				nnnfunc2:
				if( flag&0x0010 )
					wsprintf(p,"【%d】",id);
				else
					*p = '\0';
			}
		}
		return(k);
	}
	else if( id < 305 ) {		/* ﾗｲﾌﾞﾗﾘ内子ﾌﾟﾛｾｽ(256～304) */
		i = (82*(id-256));
		if( libhead ) {
			p = libhead+i;
		}
		else {
			if( openlib(10,NULL,libbuff,&libbuff[4096]) != INVALID_HANDLE_VALUE )
				p = &libbuff[i];
			else
				p = NULL;
		}
		if( pshort ) {
			if( p && *p )
				k = fstrcpycj(pshort,p,40,1);		/* ﾀｲﾄﾙ */
			else
				k = LoadString(hinst,700,pshort,48);	/* ［機能未定義］ */
		}
		if( plong ) {
			if( p && *p ) {
				i = LoadString(hinst,303,plong,32);	/* 外部ﾌﾟﾛﾌﾗﾑ:ﾀｲﾄﾙ */
				fstrcpy(plong+i,p);
			}
			else
				LoadString(hinst,700,plong,128);	/* ［機能未定義］ */
		}
		return(k);
	}
	else if( id < 346 ) {	/* ﾂｰﾙﾊﾞｰ内子ﾌﾟﾛｾｽ→ﾊﾞｰｼﾞｮﾝ7以降は無効 */
		if( pshort )
			*pshort = '\0';
		if( plong )
			*plong = '\0';
		return(k);
	}
	else if( id < ID_EXFUNC ) {	/* ﾗｲﾌﾞﾗﾘ内ｷｰﾎﾞｰﾄﾞﾏｸﾛ(346～541) */
		i = (id-346);
		i = 4096+((i/49)*4096)+((i%49)*82);
		if( libhead ) {
			p = libhead+i;
		}
		else {
			if( openlib(11,NULL,libbuff,&libbuff[4096]) != INVALID_HANDLE_VALUE )
				p = &libbuff[i];
			else
				p = NULL;
		}
		if( pshort ) {
			if( p && *p )
				k = fstrcpycj(pshort,p,40,1);	/* ｺﾒﾝﾄ */
			else
				k = fstrcpy(pshort,undefkeym);	/* [ｷｰﾎﾞｰﾄﾞﾏｸﾛ未定義] */
		}
		if( plong ) {
			if( p && *p ) {
				i = LoadString(hinst,304,plong,32);	/* ｷｰﾎﾞｰﾄﾞﾏｸﾛ:ｺﾒﾝﾄ */
				fstrcpy(plong+i,p);
			}
			else
				fstrcpy(plong,undefkeym);	/* [ｷｰﾎﾞｰﾄﾞﾏｸﾛ未定義] */
		}
		return(k);
	}
	else if( id <= ID_FNCLAST ) {	/* 一般機能番号(542～689) */
		if( pshort ) {
			if( id < 600 )		/* 542～599 */
				k = LoadString(hinst,STRIDEX1FNC1+id-ID_EXFUNC,pshort,48);
			else if( id >= ID_PPPOPEN0 && id <= ID_PPPOPEN24 ) {	/* 600～627(文字ｺｰﾄﾞ) */
				i = 0;
				if( (flag&0x0100) && ap && ap->newflg )		/* ｶﾚﾝﾄﾌｧｲﾙが新規ｳｨﾝﾄﾞｳの場合 */
					i = 1;
				getpartstr(1302,i,fmtstr,32);
				k = wsprintf(pshort,fmtstr,pppinfo[id-ID_PPPOPEN0].regname);
			}
			else if( id < 628 )		/* (文字ｺｰﾄﾞ用予備) */
				k = 0;
			else if( id < ID_MENURC1 )
				k = LoadString(hinst,id-628+STRIDEX2FNC1,pshort,48);
			else if( id < ID_HELPID )
				k = getpartstr(id-ID_MENURC1+970,1,pshort,48);
			else
				k = getpartstr(id-ID_HELPID+980,1,pshort,48);
		}
		if( plong ) {
			if( id < 600 )		/* 542～599 */
				i = LoadString(hinst,STRIDEX1FNC2+id-ID_EXFUNC,plong,128);
			else if( id >= ID_PPPOPEN0 && id <= ID_PPPOPEN24 ) {	/* 600～627(文字ｺｰﾄﾞ) */
				i = 0;
				if( (flag&0x0100) && ap && ap->newflg )
					i = 1;
				getpartstr(1301,i,fmtstr,80);
				i = wsprintf(plong,fmtstr,pppinfo[id-ID_PPPOPEN0].regname);
			}
			else if( id < 628 )		/* (文字ｺｰﾄﾞ用予備) */
				i = 0;
			else if( id < ID_MENURC1 )
				i = LoadString(hinst,id-628+STRIDEX2FNC2,plong,128);
			else if( id < ID_HELPID )
				i = getpartstr(id-ID_MENURC1+970,0,plong,128);
			else
				i = getpartstr(id-ID_HELPID+980,0,plong,128);
			if( flag&0x0010 )
				wsprintf(plong+i,"【%d】",id);
		}
		return(k);
	}
	else if( id < ID_HISTFN ) {	/* 非公開の内部機能(690～999) */
		if( id == ID_INSTAB1 ) {
			if( pshort )
				*pshort = '\0';
			if( plong )
				LoadString(hinst,1383,plong,128);
			return(k);
		}
		else if( id == ID_DELTAB1 ) {
			if( pshort )
				*pshort = '\0';
			if( plong )
				LoadString(hinst,1384,plong,128);
			return(k);
		}
		else if( id == IDS_2KEYBTN ) {	/* 2ｽﾄﾛｰｸｷｰﾎﾞﾀﾝ */
			if( keyccc > 0 ) {		/* 2ｽﾄﾛｰｸｷｰ操作中 */
				i = 1038;
				j = 0;
			}
			else if( macwait&0x8000 ) {	/* ﾏｸﾛﾌﾞﾚｰｸ中 */
				i = STRIDFNC1+ID_MACCONT;
				j = ID_MACCONT;
			}
			else if( keycccfn > 0 ) {	/* 2ｽﾄﾛｰｸｷｰﾎﾞﾀﾝに機能が定義されている */
				id = keycccfn;
				goto regen;
			}
			else {				/* 2ｽﾄﾛｰｸｷｰの機能は未定義 */
				i = 1039;
				j = ID_NOPNOP;
			}
			if( pshort )
				k = LoadString(hinst,i,pshort,48);
			if( plong ) {
				if( j > 0 && j < 250 ) {
					i = LoadString(hinst,STRIDFNC2+j,plong,128);
					if( flag&0x0010 )
						wsprintf(plong+i,"【%d】",j);
				}
				else if( j >= ID_EXFUNC && j <= ID_FNCLAST ) {
					if( j < 600 )		/* 542～599 */
						i = LoadString(hinst,STRIDEX1FNC2+j-ID_EXFUNC,plong,128);
					else if( j >= ID_PPPOPEN0 && j <= ID_PPPOPEN24 ) {	/* 文字ｺｰﾄﾞ(600～627) */
						i = 0;
						if( (flag&0x0100) && ap && ap->newflg )	/* ｶﾚﾝﾄﾌｧｲﾙが新規ｳｨﾝﾄﾞｳの場合 */
							i = 1;
						getpartstr(1301,i,fmtstr,80);
						i = wsprintf(plong,fmtstr,pppinfo[j-ID_PPPOPEN0].regname);
					}
					else if( j < 628 )	/* 文字ｺｰﾄﾞ(予備用) */
						i = 0;
					else if( j < ID_MENURC1 )
						i = LoadString(hinst,j-628+STRIDEX2FNC2,plong,128);
					else if( j < ID_HELPID )
						i = getpartstr(j-ID_MENURC1+970,0,plong,128);
					else
						i = getpartstr(j-ID_HELPID+980,0,plong,128);
					if( flag&0x0010 )
						wsprintf(plong+i,"【%d】",j);
				}
				else
					*plong = '\0';
			}
			return(k);
		}
		else if( id == IDS_2LINES ) {
			if( pshort )
				*pshort = '\0';
			if( plong )
				LoadString(hinst,1037,plong,80);
			return(k);
		}
		else if( id == IDS_SELBTN ) {		/* 選択ﾒﾆｭｰﾎﾞﾀﾝ */
			i = 0;
			boxmenu:
			if( pshort )
				k = getpartstr(1024,i,pshort,48);
			if( plong )
				*plong = '\0';
			return(k);
		}
		else if( id == IDS_FINBTN ) {		/* 検索履歴ﾒﾆｭｰﾎﾞﾀﾝ */
			i = 1;
			goto boxmenu;
		}
		else if( id == IDS_WINBTN ) {		/* ﾌｧｲﾙ履歴ﾒﾆｭｰﾎﾞﾀﾝ */
			i = 2;
			goto boxmenu;
		}
		else if( id >= IDS_CHGGUI && id <= IDS_CHGUND ) { /* 各種表示のON/OFF */
			if( pshort ) {
				k = getpartstr(1371,id-IDS_CHGGUI+1,pshort,32);
				k += getpartstr(1371,0,pshort+k,32);
			}
			if( plong )
				*plong = '\0';
			return(k);
		}
		else if( id >= IDS_TOOLBAR && id <= IDS_RBNUSER2 ) { /* 各種ﾘﾎﾞﾝのON/OFF */
			if( pshort ) {
				k = getpartstr(1372,id-IDS_TOOLBAR+1,pshort,32);
				k += getpartstr(1372,0,pshort+k,32);
			}
			if( plong )
				*plong = '\0';
			return(k);
		}
		else if( id == IDS_OTHERBTN ) {		/* ﾂｰﾙﾊﾞｰ上の「その他のﾎﾞﾀﾝ」ﾎﾞﾀﾝ */
			if( pshort )
				k = LoadString(hinst,1397,pshort,48);
			if( plong )
				*plong = '\0';
			return(k);
		}
		else
			goto illfunc;
	}
	else if( id < ID_HISTFIND ) {	/*【ﾌｧｲﾙ】ﾒﾆｭｰ中のﾌｧｲﾙ履歴(ID_HISTFN～ID_HISTFIND-1) */
		if( id < (ID_HISTFN+maxhistfn) ) {
			if( pshort )
				*pshort = '\0';
			if( plong ) {
				i = id-ID_HISTFN;
				j = (INT32)(*(WORD *)&ppedit->histfnam[i][PATHSIZE+2]);
				setfhistadd(plong,j,ppedit->histfnam[i],0);
			}
			return(k);
		}
		else
			goto illfunc;
	}
	else if( id < ID_WINDOW ) {	/* ﾂｰﾙﾊﾞｰ上の検索ﾌﾟﾙﾀﾞｳﾝﾒﾆｭｰ(ID_HISTFIND～ID_WINDOW-1) */
		if( id < (ID_HISTFIND+MAXFINDHIST) ) {
			if( pshort )
				*pshort = '\0';
			if( plong ) {
				if( (id-ID_HISTFIND) < ppmac->findhistnum ) {
					i = exsjiscopy(plong,&ppmac->areahistbuf[ppmac->findhistpos[id-ID_HISTFIND]],PURGESIZE2,0x0010);
					if( i > 0 ) {
						*(plong+(i++)) = ' ';
						*(plong+(i++)) = ' ';
						i += getfindtypestr(plong+i,ppmac->findhistid[id-ID_HISTFIND],0);
					}
				}
				else {		/* あり得ないが */
					*plong = '\0';
				}
			}
			return(k);
		}
		else
			goto illfunc;
	}
	else if( id < ID_MACFIRST ) {	/*【ｳｨﾝﾄﾞｳ】ﾒﾆｭｰ中の編集ﾌｧｲﾙ名(ID_WINDOW～ID_WINDOW+MAXTEXT-1) */
		i = id-ID_WINDOW;
		if( pshort )
			*pshort = '\0';
		if( plong )
			*plong = '\0';
		return(k);
	}
	else if( id < ID_URLFIRST ) {	/* ﾏｸﾛｺﾏﾝﾄﾞの実行(ID_MACFIRST～ID_URLFIRST-1) */
		if( pshort ) {
			k = LoadString(hinst,305,pshort,32);		/* ﾏｸﾛｺﾏﾝﾄﾞ:ｺﾏﾝﾄﾞ名 */
			k += fstrcpy(pshort+k,ppmac->cmdname[id-ID_MACFIRST]);
		}
		if( plong ) {
			i = LoadString(hinst,305,plong,32);		/* ﾏｸﾛｺﾏﾝﾄﾞ:ｺﾏﾝﾄﾞ名 */
			fstrcpy(plong+i,ppmac->cmdname[id-ID_MACFIRST]);
		}
		return(k);
	}
	else if( id < (ID_URLFIRST+MAXURLCMD) ) { /* URL/実行ﾊﾟｽ名/*.REPの実行(ID_URLFIRST～) */
		if( pshort ) {
			if( ppmac->idurldata[id-ID_URLFIRST] >= 0 )
				k = fstrcpycj(pshort,&ppmac->urldata[ppmac->idurldata[id-ID_URLFIRST]],40,1);
			else
				*pshort = '\0';
		}
		if( plong ) {
			if( ppmac->idurldata[id-ID_URLFIRST] >= 0 )
				fstrcpy(plong,&ppmac->urldata[ppmac->idurldata[id-ID_URLFIRST]]);
			else
				*plong = '\0';
		}
		return(k);
	}
	else if( ID_FNC2FIRST <= id && id <= ID_FNC2LAST ) {	/* 一般機能番号(2000～2999) */
		if( pshort ) {
			k = getpartstr(id-ID_FNC2FIRST+12000,1,pshort,48);
		}
		if( plong ) {
			i = getpartstr(id-ID_FNC2FIRST+12000,0,plong,128);
			if( flag&0x0010 )
				wsprintf(plong+i,"【%d】",id);
		}
		return(k);
	}
	else if( id >= 0x0000F000 ) {		/* ｼｽﾃﾑｺﾏﾝﾄﾞ */
		if( pshort )
			*pshort = '\0';
		if( plong ) {
			if( id == SC_SIZE )
				i = 1000;
			else if( id == SC_MOVE )
				i = 1001;
			else if( id == SC_MINIMIZE )
				i = 1002;
			else if( id == SC_MAXIMIZE )
				i = 1003;
			else if( id == SC_NEXTWINDOW )
				i = 1004;
			else if( id == SC_PREVWINDOW )
				i = 1005;
			else if( id == SC_CLOSE )
				i = 1006;
			else if( id == SC_VSCROLL )
				i = 1007;
			else if( id == SC_HSCROLL )
				i = 1008;
			else if( id == SC_KEYMENU )
				i = 1009;
			else if( id == SC_ARRANGE )
				i = 1010;
			else if( id == SC_RESTORE )
				i = 1011;
			else if( id == SC_TASKLIST )
				i = 1012;
			else
				i = 999;
			LoadString(hinst,i,plong,128);
		}
		return(k);
	}
	else {		/* その他:不当なｺﾏﾝﾄﾞID */
		illfunc:
		if( pshort )
			*pshort = '\0';
		if( plong )
			LoadString(hinst,999,plong,128);	/* 空白文字列 */
		return(k);
	}
}

INT32 adjifind(id)	/* 検索方法の調整 */
INT32 id;
{
	INT32 idnew;

	if( kmacexe == 2 )	/* ｷｰﾎﾞｰﾄﾞﾏｸﾛ実行中 */
		return(id);
	idnew = (id&FTID_METHODMASK);	/* 検索方法 */
	if( idnew == 4 || idnew == 6 ) {	/* 正規表現検索 */
		if( findcycric&0x04 )	/* 正規表現はPerl互換 */
			idnew = 6;
		else
			idnew = 4;
		id &= FTID_RANGEMASK|FTID_WORD;	/* 範囲条件/語単位は現在の方法を使う */
		id |= idnew;
	}
	return(id);
}

INT32 getfindtypestr(buff,id,flag)		/* 「検索方法」と「語単位で探す」を示す文字列を取得する */
BYTE *buff;	/* 文字列を取得するﾊﾞｯﾌｧ */
BYTE id;	/* 検索方法ID */
INT32 flag;	/* 0=ﾌﾙ文字列で取得  1=省略文字列で取得 */
{
	INT32 i,j;

	j = (INT32)(id&0x0f);
	i = getpartstr((flag==0)?70:71,j,buff,32);
	if( (id&0x10) && j != 4 && j != 6 )	/* 語単位で探す、かつ正規表現検索ではない */
		i += getpartstr(71,7,buff+i,32);
	return(i);
}

INT32 getpathstr(buff,tp,flag)
BYTE *buff;
struct ETEXT *tp;
INT32 flag;	/* ﾋﾞｯﾄ0  1=「(変更なし)」も表示する */
		/* ﾋﾞｯﾄ8  1=長いﾊﾟｽ名は省略する(dlgfx*150の幅) */
{
	INT32 i,j,k;
	BYTE upflg;

	i = tp->useflg;
	if( i == 0 ) {
		*buff = '\0';
		return(0);
	}
	else {
		upflg = tp->upflg;
		j = fstrcpy(buff,tp->outfile);
		if( tp->newflg == 0 && j > 100 && (flag&0x0100) ) {	/* 既存のﾊﾟｽ名で100ﾊﾞｲﾄ超の長いﾊﾟｽ名で省略OKの場合 */
			getabpath(buff,tp->outfile,0x00,dlgfx*150,gggfwid);
			for( j = 0 ; buff[j] ; j++ ) ;
		}
		if( i >= 50 ) {		/* ｶﾚﾝﾄｳｨﾝﾄﾞｳ2分割したｳｨﾝﾄﾞｳ */
			j += wsprintf(buff+j,"(%c/2)",tp->divflag);
			if( i >= 200 )
				upflg = ppedit->etext[i-200].upflg;
		}
		if( tp->save&0x0f )
			k = 2;		/* (読み取り専用) */
		else if( upflg )
			k = 1;		/* (変更あり) */
		else {
			if( !(flag&0x0001) )	/* (変更なし)は表示しない */
				return(j);
			k = 0;		/* (変更なし) */
		}
		j += getpartstr(1357,k,buff+j,32);
		return(j);
	}
}

INT32 setbaloon(x,y,id)		/* WM_MOUSEMOVE 時に吹き出し表示の設定を行う */
INT32 x;
INT32 y;
INT32 id;	/* -1=非表示  0～=表示すべき機能のID  */
{
	INT32 i;
	HWND hfwndbal;

#ifdef SDILISTWIN
	hfwndbal = (hfwnd?hfwnd:sdilisthwnd);
#else
	hfwndbal = hfwnd;
#endif
	if( !(sysmode&SYS_BALOON) )
		return(0);
	if( balskip > 0 ) {
		balskip--;
		return(0);
	}
	if( baloonid >= 0 ) {	/* 吹き出し表示中 */
		if( id != baloonid ) {
			endbaloon();
			if( id >= 0 ) {
				balwait = id;
				SetTimer(hfwndbal,ID_CHGTBAR,200,NULL);
			}
		}
	}
	else if( balwait >= 0 ) { /* 吹き出し表示待ち */
		if( id != balwait ) {
			KillTimer(hfwndbal,ID_CHGTBAR);
			balwait = -1;
		}
	}
	else {
		if( id >= 0 && ( x != oldbtnxx || y != oldbtnyy ) ) {
			balwait = id;
			if( oldbtnxx == -2 )
				i = 200;
			else if( oldbtnxx == -1 )
				i = 10;
			else
				i = 800;
			SetTimer(hfwndbal,ID_CHGTBAR,i,NULL);
		}
	}
	oldbtnid = id;
	oldbtnxx = x;
	oldbtnyy = y;
	return(1);
}

INT32 timebaloon(hfwndbal)	/* WM_TIMER ﾒｯｾｰｼﾞ時に吹き出しを表示する */
HWND hfwndbal;
{
	INT32 i,j;
	HWND hwnd;
	struct ETEXT *tp;
	POINT pt;

	KillTimer(hfwndbal,ID_CHGTBAR);
	if( !(sysmode&SYS_BALOON) ) {
		balwait = -1;
		return(0);
	}
	if( balwait >= 0 ) {	/* 吹き出し表示待ち */
		if( balwait < 1010 ) {		/* ﾌﾚｰﾑｳｨﾝﾄﾞｳ中のﾎﾞﾀﾝ */
			hwnd = hfwnd;
			i = 0;
		}
		else if( balwait < 1020 ) {	/* 編集子ｳｨﾝﾄﾞｳ中のﾎﾞﾀﾝ */
			if( ap == NULL ) {
				balwait = -1;
				return(0);
			}
			hwnd = ap->hwnd;
			i = 1;
			tp = mp;
			setmp(ap);
		}
		else if( balwait < 1100 ) {	/* ﾘｽﾄｳｨﾝﾄﾞｳ中のﾎﾞﾀﾝ */
			if( hwndlstwin == NULL || (LSTWINSTAT&0x30) == 0x00 ) {
				balwait = -1;
				return(0);
			}
			hwnd = hwndlstwin;
			i = 2;
		}
		else if( balwait >= 2000 && balwait < 3000 ) {	/* 多目的ﾊﾞｰ中のﾎﾞﾀﾝ/ﾀｸﾞ */
			hwnd = hfwnd;
			i = 0;
		}
		else if( balwait >= 3000 ) {	/* ﾘｽﾄｳｨﾝﾄﾞｳ中のﾘｽﾄ項目 */
			if( hwndlstwin == NULL || (LSTWINSTAT&0x30) == 0x00 ) {
				balwait = -1;
				return(0);
			}
			hwnd = hwndlstwin;
			i = 2;
		}
		else {
			balwait = -1;
			return(0);
		}
		GetCursorPos(&pt);
		ScreenToClient(hwnd,&pt);
		if( finditem(i,pt.x,pt.y) != balwait ) {	/* ﾀｲﾏｰ待ちの間にﾏｳｽｶｰｿﾙを大きく移動した */
			j = 0;
			goto donebal;
		}
		if( startbaloon(balwait,pt.x,pt.y) == 0 ) {	/* 吹き出しが表示できなかった */
			j = 0;
			goto donebal;
		}
		/* 吹き出しを表示した */
		SetCapture(hwnd);
		j = 1;
		donebal:
		balwait = -1;
		if( i == 1 )		/* 編集子ｳｨﾝﾄﾞｳ中のｱｲﾃﾑ */
			setmp(tp);
		return(j);
	}
	return(0);
}

INT32 startbaloon(id,x,y)		/* 吹き出し表示開始 */
INT32 id;
INT32 x;
INT32 y;
{
	INT32 i,j,k;
	HWND hwnd;
	BYTE *ddd,buff[PATHSIZE+128];

	hwnd = hfwnd;
	if( id < 0 )
		return(0);
	else if( id < 1000 ) {		/* ﾂｰﾙﾊﾞｰ内ｱｲﾃﾑ */
		x = rbnitem[id].x0;
		y = rbnrow[rbnitem[id].row].y1+8;
		i = rbnitem[id].id;
		if( i == 20 ) {		/* ｶﾚﾝﾄｳｨﾝﾄﾞｳ名表示ﾎﾞｯｸｽ */
			if( ap ) {	/* ｶﾚﾝﾄｳｨﾝﾄﾞｳが存在する */
				k = getpathstr(buff,ap,0x0000);
				goto balgo;
			}
			j = ID_OPENLIST;
		}
		else {
			if( (j=btnfunc(id)) < 0 )
				return(0);
		}
		if( j >= ID_POPMENU0 && j <= ID_POPMENU9 ) {
			getfuncstr(j,0x0000,NULL,buff,NULL);
		}
		else {
			if( getfuncstr(j,0x0011,buff,NULL,NULL) == 0 )
				return(0);
		}
	}
	else if( id < 1010 ) {		/* 多目的ﾊﾞｰ左端のﾎﾞﾀﾝ/検索ﾎﾞｯｸｽ */
		x -= 16;
		y += 16;
		if( id == 1000 )	/* ←へｽｸﾛｰﾙ */
			k = getpartstr(1359,0,buff,32);
		else if( id == 1001 )	/* →へｽｸﾛｰﾙ */
			k = getpartstr(1359,1,buff,32);
		else if( id == 1002 ) 	/* ﾘｽﾄｳｨﾝﾄﾞｳ表示 */
			k = getpartstr(1359,2,buff,32);
		else if( id == 1005 )	/* 検索ﾎﾞｯｸｽ中の入力枠 */
			k = getfindtypestr(buff,adjifind(ifind),0);
		else
			return(0);
	}
	else if( id < 1020 ) {		/* ｶﾞｲﾄﾞﾗｲﾝ上の4つのﾎﾞﾀﾝ */
		if( ap == NULL || ap != mp )
			return(0);
		x -= 16;
		y += 16;
		j = -1;
		if( id == 1010 ) {	/* ｶﾞｲﾄﾞﾗｲﾝ右端から3番目のﾎﾞﾀﾝ */
			if( mp->newflg == 3 )		/* ﾀｸﾞｳｨﾝﾄﾞｳ */
				getpartstr(683,6,buff,48);
			else if( mp->newflg == 4 )	/* DOSｼｪﾙｴｽｹｰﾌﾟ･ｳｨﾝﾄﾞｳ */
				getpartstr(683,0,buff,48);
			else
				j = ID_CHGOMODE;
		}
		else if( id == 1011 ) {	/* ｶﾞｲﾄﾞﾗｲﾝ右端から2番目のﾎﾞﾀﾝ */
			if( mp->bin2mode )
				j = ID_BINOPESET;
			else if( mp->newflg == 3 ) {	/* ﾀｸﾞｳｨﾝﾄﾞｳ */
				if( *(DWORD *)(mp->base+STARTSSS-4) == DIFFMARK )	/* ﾌｧｲﾙ比較結果ｳｨﾝﾄﾞｳ */
					getpartstr(683,1,buff,48);
				else					/* ｸﾞﾛｰﾊﾞﾙ検索結果ｳｨﾝﾄﾞｳ */
					getpartstr(683,9,buff,48);
			}
			else if( mp->newflg == 4 )	/* DOSｼｪﾙｴｽｹｰﾌﾟ･ｳｨﾝﾄﾞｳ */
				getpartstr(683,2,buff,48);
			else {				/* 通常ｳｨﾝﾄﾞｳ */
				if( ( mp->readcode==0 && mp->indll[0] ) || ( mp->savecode==0 && mp->outdll[0] ) )	/* 外部ﾌﾟﾘ/ﾎﾟｽﾄﾌﾟﾛｾｯｻが設定されている場合 */
					getpartstr(683,8,buff,48);
				else if( mp->newflg == 0 )	/* 通常の既存ﾌｧｲﾙのｳｨﾝﾄﾞｳ */
					getpartstr(683,7,buff,48);
				else				/* 新規ﾌｧｲﾙのｳｨﾝﾄﾞｳ */
					return(0);
			}
		}
		else if( id == 1012 ) {	/* ｶﾞｲﾄﾞﾗｲﾝ右端から1番目のﾎﾞﾀﾝ */
			if( mp->bin2mode )
				j = ID_BINORDER;
			else if( mp->newflg == 3 ) {	/* ﾀｸﾞｳｨﾝﾄﾞｳ */
				if( mp->orgfile[0] == MKALLSS )	/* ｸﾞﾛｰﾊﾞﾙ検索の単純検索 */
					getpartstr(683,3,buff,48);
				else
					getpartstr(683,4,buff,48);
			}
			else if( mp->newflg == 4 )	/* DOSｼｪﾙｴｽｹｰﾌﾟ･ｳｨﾝﾄﾞｳ */
				j = ID_CHGENV;
			else
				j = ID_GOKEYWD;
		}
		else if( id == 1013 ) {	/* 文字ｺｰﾄﾞ表示の切り替えﾎﾞﾀﾝ */
			if( mp->bin2mode )
				return(0);
			getpartstr(683,5,buff,48);
		}
		else if( id == 1015 ) {	/* 入力改行コードの切り替えﾎﾞﾀﾝ */
			if( mp->bin2mode )
				return(0);
			getpartstr(683,10,buff,48);
		}
		else if( id == 1014 ) {	/* 桁ｹﾞｰｼﾞ上の「B」ﾏｰｸ */
			if( mp->bin2mode )
				return(0);
			j = ID_BKMARKLST;
		}
		else
			return(0);
		if( j >= 0 ) {
			if( getfuncstr(j,0x0000,buff,NULL,NULL) == 0 )
				return(0);
		}
		hwnd = mp->hwnd;
	}
	else if( id < 1100 ) {		/* ﾘｽﾄｳｨﾝﾄﾞｳ上のﾎﾞﾀﾝ等 */
		if( hwndlstwin == NULL )
			return(0);
		ddd = (BYTE *)hlistmem[0];
		if( id >= 1040 ) {	/* 機能ﾎﾞﾀﾝ */
			k = getpartstr(1394,id-1040,buff,64);
		}
		else if( id == 1039 ) {	/* ﾀｲﾄﾙﾊﾞｰ */
			k = getpartstr(1360,0,buff,64);
			if( (LSTWINSTAT&0x30) == 0x20 )	;/* ﾂｰﾙﾊﾞｰのみの場合 */
			else {
				buff[k++] = 0x0d;	/* 改行 */
				getpartstr(1360,1,&buff[300],64);
				if( *(ddd+34) == LIDFILEHIST )
					j = 5;		/*「ﾌｫﾙﾀﾞ」ﾘｽﾄ */
				else if( *(ddd+34) == LIDFOLDER ) {
					if( ppedit->nlmark > 0 )
						j = 6;	/*「ﾌﾞｯｸﾏｰｸ」ﾘｽﾄ */
					else
						j = 2;	/*「ﾌｧｲﾙ履歴」ﾘｽﾄ*/
				}
				else
					j = 2;		/*「ﾌｧｲﾙ履歴」ﾘｽﾄ*/
				getpartstr(391,j,&buff[200],64);
				wsprintf(&buff[k],&buff[300],&buff[200]);
			}
		}
		else if( id == 1032 ) {	/* 検索ﾎﾞｯｸｽ */
			k = getpartstr(1361,0,buff,200);
		}
		else if( id >= 1030 && id <= 1031 ) {	/* 横ｽｸﾛｰﾙﾎﾞﾀﾝ */
			k = getpartstr(1360,id-1030+2,buff,64);
		}
		else if( id == 1029 ) {	/* ﾀｲﾄﾙﾊﾞｰ上の「X」ﾎﾞﾀﾝ */
			k = getpartstr(389,6,buff,64);
		}
		else if( id == 1028 ) {	/* ﾀｲﾄﾙﾊﾞｰ上の「▼」ﾎﾞﾀﾝ */
			k = getpartstr(1394,0,buff,64);
		}
		else if( id >= 1024 && id <= 1027 ) {	/*「ﾌｫﾙﾀﾞ」ﾘｽﾄのﾘｽﾄ外2項目 */
			k = getdircond(id,ddd,buff);
		}
		else if( id == 1023 ) {	/*「ｿｰﾄ方法」表示上 */
			k = getpartstr(391,9,buff,32);
			getsortid(ddd,&i,&j);
			k += getpartstr(i,j,buff+k,64);
		}
		else if( id == 1022 ) {	/*「ｿｰﾄ方法」ｺﾝﾎﾞﾎﾞｯｸｽのﾌﾟﾙﾀﾞｳﾝﾎﾞﾀﾝ */
			k = getpartstr(1026,0,buff,48);
		}
		else
			return(0);
		x -= 16;
		y += 16;
		hwnd = hwndlstwin;
	}
	else if( id >= 2000 && id < 3000 ) {	/* 多目的ﾊﾞｰ上の編集ﾌｧｲﾙ名 */
		x -= 50;
		y += 18;
		j = getlowfunc(id);
		if( j >= 0 && j < 1000 ) {	/* ﾌｧﾝｸｼｮﾝｷｰ表示 */
			if( keydef[j] >= 1 ) {
				j = keydef[j];
				return(0);	/* ﾌｧﾝｸｼｮﾝｷｰ表示の吹き出しは表示しない */
			}
		}
		else if( j >= 1000 ) {		/* 編集ﾌｧｲﾙ名の表示 */
			j -= 1000;
			if( j < MAXTEXT ) {
				if( getpathstr(buff,&ppedit->etext[j],0x0000) > 0 )
					goto balgo;
			}
			else if( j == MAXTEXT ) {
				getfuncstr(ID_NEWOPEN,0x0000,NULL,buff,NULL);
				goto balgo;
			}
			else if( j == (MAXTEXT+1) ) {
				getfuncstr(ID_QUIT,0x0000,NULL,buff,NULL);
				goto balgo;
			}
		}
		return(0);
	}
	else if( id >= 3000 ) {		/* ﾘｽﾄｳｨﾝﾄﾞｳ上のﾘｽﾄ項目 */
		if( hwndlstwin == NULL )
			return(0);
		x = lstwinx0[lstwinlstid];
		y += 18;
		ddd = (BYTE *)hlistmem[0];
		if( lstwinfc == 0 )
			return(0);
		if( (getitemstr(buff,ddd,id-3000,1)&0x0000ffff) == 0 )
			return(0);
		hwnd = hwndlstwin;
	}
	else
		return(0);
	balgo:
	if( hwnd == NULL )
		return(0);
	baloon = balwind(buff,hwnd,x,y);
	baloonid = id;
	return(1);
}

HWND balwind(buff,hwnd,x,y)
BYTE *buff;	/* 吹き出し表示文字列(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ、ただし0x0dで改行) */
HWND hwnd;
INT32 x;
INT32 y;
{
	INT32 i,x0,y0,xw,yw,xx,yy,cx,cy;
	BYTE *p,*p1,c;
	WCHAR wbuff[512];
	HWND hwndbal;
	HFONT oldfont;
	HDC thdc;
	SIZE sz;
	POINT pt;

	thdc = GetDC(NULL);
	oldfont = SelectObject(thdc,hbalf);
	cx = 0;
	cy = 0;
	for( p = buff ; ; ) {
		for( p1 = p ; ; ) {
			if( ctypesjis[*p]&CASCII )
				p++;
			else if( ctypesjis[*p]&CKANJI1 )
				p += 2;
			else if( ctypesjis[*p]&CUNIMARK ) {
				if( *p == UCS2MARK )
					p += 3;
				else
					p += 5;
			}
			else
				break;
		}
		c = *p;
		*p = '\0';
		i = exsjistounicode(p1,wbuff);
		*p = c;
		GetTextExtentPoint32W(thdc,wbuff,i,&sz);
		if( sz.cx > cx )
			cx = sz.cx;
		cy += balfy;
		if( c != 0x0d )		/* 改行ﾏｰｸ以外 */
			break;
		p++;
	}
	*p = '\0';
	cx += 4;	/* 縦線の幅1+左端1+右端1+縦線の幅1 */
	cy += 4;	/* 横線の幅1+上部1+下部1+横線の幅1 */
	SelectObject(thdc,oldfont);
	ReleaseDC(NULL,thdc);
	pt.x = x;
	pt.y = y;
	ClientToScreen(hwnd,&pt);
	x0 = GetSystemMetrics(SM_XVIRTUALSCREEN);
	y0 = GetSystemMetrics(SM_YVIRTUALSCREEN);
	xw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
	yw = GetSystemMetrics(SM_CYVIRTUALSCREEN);
	xx = GetSystemMetrics(SM_CXSCREEN);
	yy = GetSystemMetrics(SM_CYSCREEN);
	if( pt.x < x0 )
		pt.x = x0;
	else if( (pt.x+cx) > (x0+xw) )
		pt.x = x0+xw-cx;
	if( pt.y < y0 )
		pt.y = y0;
	else if( (pt.y+cy) > (y0+yw) )
		pt.y = y0+yw-cy;
	balactive = 1;	/* ﾌﾚｰﾑｳｨﾝﾄﾞｳのﾀｲﾄﾙﾊﾞｰ表示の変更を禁止する */
	hwndbal = CreateWindowEx(WS_EX_TOPMOST,
			miclasb,buff,WS_POPUP|WS_VISIBLE|WS_DISABLED,
			pt.x,pt.y,cx,cy,hwnd,(HMENU)NULL,hinst,NULL);
	balactive = 0;	/* ﾌﾚｰﾑｳｨﾝﾄﾞｳのﾀｲﾄﾙﾊﾞｰ表示の変更を許可する */
	return(hwndbal);	/* 吹き出しｳｨﾝﾄﾞｳを返す */
}

INT32 endbaloon()
{
	INT32 i;

	i = 0;
	if( balwait >= 0 ) {	/* 吹き出し表示待ちならｷｬﾝｾﾙ  */
#ifdef SDILISTWIN
		KillTimer(hfwnd?hfwnd:sdilisthwnd,ID_CHGTBAR);
#else
		KillTimer(hfwnd,ID_CHGTBAR);
#endif
		balwait = -1;
	}
	if( baloonid >= 0 ) {	/* 吹き出し表示中なら消去 */
		ReleaseCapture();
		if( baloon ) {
			DestroyWindow(baloon);
			i = 1;
		}
		baloon = NULL;
		baloonid = -1;
	}
	return(i);
}

INT32 dispbaloon(hWnd,thdc)	/* 吹き出しｳｨﾝﾄﾞｳの表示 */
HWND hWnd;
HDC thdc;
{
	INT32 n,y,yx;
	RECT rc;
	HFONT oldfont;
	BYTE *p,*p1,c,buff[PATHSIZE+256];
	WCHAR wbuff[PATHSIZE+256];

	n = GetWindowText(hWnd,buff,510);
	GetClientRect(hWnd,&rc);
	oldfont = SelectObject(thdc,hbalf);
	SetTextColor(thdc,GetSysColor(COLOR_INFOTEXT));
	SetBkColor(thdc,GetSysColor(COLOR_INFOBK));
	MoveToEx(thdc,0,0,NULL);
	LineTo(thdc,rc.right-1,0);
	LineTo(thdc,rc.right-1,rc.bottom-1);
	LineTo(thdc,0,rc.bottom-1);
	LineTo(thdc,0,0);
	rc.left = rc.top = 1;
	rc.right--;
	y = 2;
	yx = rc.bottom-1;
	for( p=buff,y=2 ; ; ) {
		for( p1 = p ; ; ) {
			if( ctypesjis[*p]&CASCII )
				p++;
			else if( ctypesjis[*p]&CKANJI1 )
				p += 2;
			else if( ctypesjis[*p]&CUNIMARK ) {
				if( *p == UCS2MARK )
					p += 3;
				else
					p += 5;
			}
			else
				break;
		}
		c = *p;
		*p = '\0';
		n = exsjistounicode(p1,wbuff);
		*p = c;
		rc.bottom = ((c==0x0d)?(y+balfy):yx);
		ExtTextOutW(thdc,2,y,ETO_OPAQUE,&rc,wbuff,n,NULL);
		if( c != 0x0d )		/* 改行ﾏｰｸ以外 */
			break;
		p++;
		rc.top = rc.bottom;
		y += balfy;
	}
	SelectObject(thdc,oldfont);
	return(1);
}

INT32 dragbaloon(flag,x,y,col)	/* 桁ｹﾞｰｼﾞ上の折り返しﾏｰｸ/ｿﾌﾄﾀﾌﾞﾏｰｸ/非等間隔ﾊｰﾄﾞﾀﾌﾞﾏｰｸをﾄﾞﾗｯｸﾞ中の吹き出し表示 */
INT32 flag;	/* 0=表示開始  1=表示変更  2=表示終了 */
INT32 x;
INT32 y;
INT32 col;	/* ﾄﾞﾗｯｸﾞ中の桁位置(1～) */
{
#ifdef CSVEDIT
	INT32 width;
#endif
	POINT po;
	BYTE buff[32];

	if( flag >= 1 ) {
		if( baloon ) {
			DestroyWindow(baloon);
			baloon = NULL;
			baloonid = -1;
		}
	}
	if( flag < 2 ) {
#ifdef CSVEDIT
		if( mleft == 6 ) {
			width = ((mmtabid==0)?(col-1):(col-1-mp->tabstoph[mmtabid-1]));
			wsprintf(buff,"[%d]=%d桁",mmtabid+1,(mmtabid==0)?width:(width-1));	/* ｾﾙの横幅(1列目=列幅,2列目～=列幅-1) */
		}
		else
			wsprintf(buff,"%4d 桁",col);
#else
		wsprintf(buff,"%4d 桁",col);
#endif
		po.x = x-(x%mp->x1)-(mp->x1*4);
		po.y = mp->guidey+mp->coly+8;
		ClientToScreen(mp->hwnd,&po);
		ScreenToClient(hfwnd,&po);
		baloon = balwind(buff,hfwnd,po.x,po.y);
		baloonid = 1010;
	}
	return(flag);
}

void holescreen()	/* ｽｸﾘｰﾝ全体の位置とｻｲｽﾞの情報を取得する(ﾏﾙﾁﾓﾆﾀを考慮) */
{
	RECT rcw;

	if( osflag == 2 || osflag == 3 || osflag >= 5 ) {/* Windows98/ME/2000/XP以降 */
		if( GetSystemMetrics(SM_CMONITORS) == 1 ) {	/* ｼﾝｸﾞﾙﾓﾆﾀ */
			SystemParametersInfo(SPI_GETWORKAREA,0,&rcw,0);	/* ﾌﾟﾗｲﾏﾘﾓﾆﾀの位置とｻｲｽﾞを取得する */
			x000 = rcw.left;
			y000 = rcw.top;
			xw00 = rcw.right-rcw.left;
			yw00 = rcw.bottom-rcw.top;
		}
		else {		/* ﾏﾙﾁﾓﾆﾀ */
			x000 = GetSystemMetrics(SM_XVIRTUALSCREEN);
			y000 = GetSystemMetrics(SM_YVIRTUALSCREEN);
			xw00 = GetSystemMetrics(SM_CXVIRTUALSCREEN);
			yw00 = GetSystemMetrics(SM_CYVIRTUALSCREEN);
		}
	}
	else {		/* Windows 95/NT3.51/NT4.0 */
		x000 = 0;
		y000 = 0;
		xw00 = GetSystemMetrics(SM_CXFULLSCREEN);
		yw00 = GetSystemMetrics(SM_CYFULLSCREEN);
	}
}

void getwinwork(hwnd,x0,y0,xw,yw)	/* ｽｸﾘｰﾝ内のｳｨﾝﾄﾞｳ整列用領域の位置とｻｲｽﾞの情報を取得する(ﾏﾙﾁﾓﾆﾀを考慮) */
HWND hwnd;	/* このｳｨﾝﾄﾞｳと最も大きく重なるﾓﾆﾀの作業領域の情報を取得する */
INT32 *x0;	/* ﾓﾆﾀの左上位置のｽｸﾘｰﾝ座標(X座標)	*/
INT32 *y0;	/* ﾓﾆﾀの左上位置のｽｸﾘｰﾝ座標(Y座標)	*/
INT32 *xw;	/* ﾓﾆﾀの横幅(ﾋﾟｸｾﾙ)			*/
INT32 *yw;	/* ﾓﾆﾀの高さ(ﾋﾟｸｾﾙ)			*/
{
	HINSTANCE hlib;
	FARPROC proc1,proc2;
	DWORD hmon;
	struct MONITORINFO moninfo;

	if( osflag == 2 || osflag == 3 || osflag >= 5 ) {	/* Windows98/ME/2000/XP/Vista */
		if( (hlib=LoadLibrary("USER32.DLL")) ) {
			if( (proc1=GetProcAddress(hlib,"MonitorFromWindow")) && 
				(proc2=GetProcAddress(hlib,"GetMonitorInfoA")) ) {
				hmon = (DWORD)(*proc1)(hwnd,MONITOR_DEFAULTTOPRIMARY);/* ｶﾚﾝﾄｳｨﾝﾄﾞｳと重なるﾓﾆﾀを取得する */
				moninfo.cbSize = sizeof(struct MONITORINFO);
				(*proc2)(hmon,&moninfo);	/* ｶﾚﾝﾄｳｨﾝﾄﾞｳと重なるﾓﾆﾀの情報を取得する */
				/* 指定ﾓﾆﾀのﾀｽｸﾊﾞｰを除いた領域(rcWork)を得る */
				*x0 = moninfo.rcWork.left;
				*y0 = moninfo.rcWork.top;
				*xw = moninfo.rcWork.right-moninfo.rcWork.left;
				*yw = moninfo.rcWork.bottom-moninfo.rcWork.top;
				FreeLibrary(hlib);
				return;
			}
			FreeLibrary(hlib);
		}
	}
	*x0 = 0;
	*y0 = 0;
	*xw = GetSystemMetrics(SM_CXFULLSCREEN);
	*yw = GetSystemMetrics(SM_CYFULLSCREEN);
}

RECT getwinworkrect(hwnd)
HWND hwnd;
{
	RECT rect;

	/* x0,y0,xw,yw */
	getwinwork(hwnd, &rect.left, &rect.top, &rect.right, &rect.bottom);

	/* xw,ywをx1,y1へ変換 */
	rect.right  += rect.left;
	rect.bottom += rect.top;

	return rect;
}

INT32 chkfindcbtn(flag)	/* MEDITｺﾝﾄﾛｰﾙ入力の開始/終了時における、ﾂｰﾙﾊﾞｰ上の再検索ﾎﾞﾀﾝの有効/無効の切り替え */
INT32 flag;	/* 0=MEDITｺﾝﾄﾛｰﾙ入力の開始時  1=MEDITｺﾝﾄﾛｰﾙ入力の終了時 */
{
	INT32 id,func;
	HDC thdc;

	if( ppedit->strfind[0] == '\0' && nrbnitem > 0 ) {	/* ｶﾚﾝﾄ検索文字列がない */
		thdc = GetDC(hfwnd);
		for( id = findbtn+2 ; id < nrbnitem ; id++ ) {	/* 検索ﾎﾞｯｸｽの次の次のﾎﾞﾀﾝからﾁｪｯｸ */
			func = btnfunc(id);
			if( func == ID_FINDFC || func == ID_FINDBC || func == ID_FINDALLC ) {
				if( flag == 0 )		/* MEDITｺﾝﾄﾛｰﾙ入力の開始時 */
					dispbtn(thdc,id,0);	/* 再検索ﾎﾞﾀﾝを有効ﾎﾞﾀﾝとする */
				else			/* MEDITｺﾝﾄﾛｰﾙ入力の終了時 */
					dispbtn(thdc,id,10);	/* 再検索ﾎﾞﾀﾝを無効ﾎﾞﾀﾝとする */
			}
			else
				break;
		}
		ReleaseDC(hfwnd,thdc);
		return(1);
	}
	return(0);
}

INT32 chkallbtn(flag)	/* ﾂｰﾙﾊﾞｰとﾕｰｻﾞｰ定義ﾊﾞｰと多目的ﾊﾞｰの更新表示 */
INT32 flag;	/* 0=すべてをﾁｪｯｸ  1=①と②のｳｨﾝﾄﾞｳが必要なﾎﾞﾀﾝのみをﾁｪｯｸ  2=ﾂｰﾙﾊﾞｰのみをﾁｪｯｸ */
{
	INT32 i,n,id;
	HDC thdc;

	/* ﾂｰﾙﾊﾞｰとﾕｰｻﾞｰ定義ﾊﾞｰの更新表示 */
	thdc = GetDC(hfwnd);
	for( id=n=0 ; id < nrbnitem ; id++ ) {
		if( flag == 1 ) {
			if( (i=btnfunc(id)) < 0 )
				continue;
			if( ID_FNC2FIRST <= i && i <= ID_FNC2LAST )
				i = i-ID_FNC2FIRST+256+148;	/* 2000～2999 */
			if( !(idfunc[i]&FUNC_DUAL) )
				continue;
		}
		if( chkbtnfunc(id) ) {	/* 有効な機能番号 */
			if( rbnitem[id].dsp != 1 ) {
				if( rbnitem[id].id == 21 || rbnitem[id].id == 22 ) {
					dispbox(thdc,id,1);
					rbnitem[id].dsp = 1;
				}
				else
					dispbtn(thdc,id,0);
				n++;
			}
		}
		else {			/* 無効な機能番号 */
			if( rbnitem[id].dsp != 0 ) {
				if( rbnitem[id].id == 21 || rbnitem[id].id == 22 ) {
					dispbox(thdc,id,2);
					rbnitem[id].dsp = 0;
				}
				else
					dispbtn(thdc,id,10);
				n++;
			}
		}
	}
	ReleaseDC(hfwnd,thdc);
	if( flag >= 1 )
		return(n);
	/* 多目的ﾊﾞｰの更新表示 */
	if( messp == 0 && framey2 > 0 && messt < 20 && mesdd >= 0 && mesdd <= 4 ) {	/* 多目的ﾊﾞｰがﾌｧﾝｸｼｮﾝｷｰ表示の時 */
		for( i=id=0 ; i < DISPFUNC ; i++ ) {
			if( ( dspfuncfunc[i] >= ID_FNCFIRST && dspfuncfunc[i] < 250 ) || 
				( dspfuncfunc[i] >= ID_EXFUNC && dspfuncfunc[i] <= ID_FNCLAST ) ||
				( dspfuncfunc[i] >= ID_FNC2FIRST && dspfuncfunc[i] <= ID_FNC2LAST ) ) {
				if( getmfs(dspfuncfunc[i]) == MFS_ENABLED ) { /* 有効な機能番号 */
					if( dspfuncgray[i] )
						id++;
				}
				else {			/* 無効な機能番号 */
					if( dspfuncgray[i] == 0 )
						id++;
				}
			}
		}
		if( id > 0 ) {		/* 有効/無効が変化したﾎﾞﾀﾝが1つ以上ある */
			mesdd = -4;
			dispmmm(0,"");
		}
	}
	return(n);
}

INT32 chkbtnfunc(id)		/* ﾎﾞﾀﾝ機能の有効(1)/無効(0)を返す */
INT32 id;	/* ﾎﾞﾀﾝのID */
{
	INT32 i;

	if( (i=btnfunc(id)) < 0 )
		return(0);
	if( i == IDS_OTHERBTN )
		return(1);
	else if( i >= IDS_SELBTN && i < 1000 ) {	/* 実行するのにｶﾚﾝﾄｳｨﾝﾄﾞｳが必要な機能 */
		if( ap == NULL )
			return(0);
		if( pbox ) {
			if( getmfs(i) == MFS_GRAYED )
				return(0);
		}
	}
	else {			/* その他の機能 */
		if( getmfs(i) == MFS_GRAYED )
			return(0);
	}
	return(1);	/* 機能は有効 */
}

void dispbox(thdc,id,flag)
HDC thdc;
INT32 id;
INT32 flag;	/* 枠表示ﾌﾗｸﾞ  0=枠表示なし  1=枠を表示  2=枠を表示(無効表示をﾁｪｯｸ) */
{
	dispbox1(thdc,rbnitem[id].x0,rbnrow[rbnitem[id].row].y0,
		(INT32)rbnitem[id].cx,rbnrow[rbnitem[id].row].y1,
		(INT32)rbnitem[id].id,flag,colortab);
}

void dispcurr(tp)	/* 「ｳｨﾝﾄﾞｳ」ﾎﾞｯｸｽの表示 */
struct ETEXT *tp;
{
	HDC thdc;

	if( tp ) {
		if( tp->newflg == 0 ) {
#ifdef BOXINTOOLBAR
			getabpath(txtxxt,tp->outfile,0x01,(dlgfx*xguiwin)-6,gggfwid);
#else
			getabpath(txtxxt,tp->outfile,0x01,dlgfx*(xguiwin-10),gggfwid);
#endif
		}
		else
			fstrcpy(txtxxt,tp->outfile);
	}
	else {
		txtxxt[0] = '\0';
	}
	if( txtxxx >= 0 ) {
		thdc = GetDC(hfwnd);
		dispbox(thdc,txtxxx,0);
		ReleaseDC(hfwnd,thdc);
	}
}

void dispsel(tp)	/* 「選択」ﾎﾞｯｸｽの表示 */
struct ETEXT *tp;	/* 必ず NULL でない */
{
	INT32 i;
	BYTE selid;
	HDC thdc;

	if( tp ) {
#ifdef SELMODENEW
		selid = tp->selflg;
#else
		selid = selflg;
#endif
		if( selid == 3 && tp->bin2mode )
			i = 5;
#ifdef CSVEDIT
		else if( tp->csvselflg )
			i = 6;
#endif
		else
			i = selid;
	}
	else {
		i = 0;
	}
	fstrcpy(selxxt,selmess[i]);
	if( selxxx >= 0 ) {	/* 「選択」ﾎﾞｯｸｽがある */
		thdc = GetDC(hfwnd);
		dispbox(thdc,selxxx,0);
		ReleaseDC(hfwnd,thdc);
	}
}

void dispfin()
{
	HDC thdc;

	if( finxxx >= 0 ) {	/* ﾂｰﾙﾊﾞｰ上に検索ﾎﾞｯｸｽがある */
		thdc = GetDC(hfwnd);
		dispbox(thdc,finxxx,0);
		ReleaseDC(hfwnd,thdc);
	}
}

INT32 dispfinbtn(p,id)	/* ｶﾚﾝﾄ検索文字列の設定とﾂｰﾙﾊﾞｰ表示 */
BYTE *p;	/* ｶﾚﾝﾄ検索文字列に設定する検索文字列(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
INT32 id;	/* ｶﾚﾝﾄ検索文字列の検索ID */
{
	INT32 i;
	BYTE oldc;

	oldc = ppedit->strfind[0];
	i = fstrcpy(ppedit->strfind,p);
	ppedit->idfind = id;
	if( hfwnd ) {		/* ﾌﾚｰﾑｳｨﾝﾄﾞｳが存在する */
		dispfin();	/* ﾂｰﾙﾊﾞｰ上の検索ﾎﾞｯｸｽを再表示 */
		if( oldc == '\0' )	/* それまではｶﾚﾝﾄ検索文字列が存在しなかった */
			chkallbtn(2);	/* ﾂｰﾙﾊﾞｰ上の全ﾎﾞﾀﾝの有効/無効を再表示 */
	}
	return(i);
}

void disprbn(thdc)	/* ﾂｰﾙﾊﾞｰおよび多目的ﾊﾞｰを描画 */
HDC thdc;
{
	INT32 i;

	wakubtnid = -1;
	if( btncheck ) {	/* 有効ﾎﾞﾀﾝのﾁｪｯｸの必要あり */
		btncheck = 0;
		for( i = 0 ; i < nrbnitem ; i++ ) {
			if( rbnitem[i].id < 20 ) {
				if( chkbtnfunc(i) )	/* 有効な機能番号 */
					dispbtn(thdc,i,0);
				else			/* 無効な機能番号 */
					dispbtn(thdc,i,10);
			}
			else if( rbnitem[i].id == 20 ) 
				dispbox(thdc,i,1);
			else if( rbnitem[i].id == 21 || rbnitem[i].id == 22 ) {
				if( chkbtnfunc(i) ) {	/* 有効な機能番号 */
					dispbox(thdc,i,1);
					rbnitem[i].dsp = 1;
				}
				else {			/* 無効な機能番号 */
					dispbox(thdc,i,2);
					rbnitem[i].dsp = 0;
				}
			}
			dispsepa(thdc,i);
		}
	}
	else {			/* 有効ﾎﾞﾀﾝのﾁｪｯｸの必要なし */
		for( i = 0 ; i < nrbnitem ; i++ ) {
			if( rbnitem[i].id < 20 ) {
				if( rbnitem[i].dsp == 0 )
					dispbtn(thdc,i,10);
				else
					dispbtn(thdc,i,0);
			}
			else if( rbnitem[i].id == 20 )
				dispbox(thdc,i,1);
			else if( rbnitem[i].id == 21 || rbnitem[i].id == 22 ) {
				if( rbnitem[i].dsp == 0 )
					dispbox(thdc,i,2);
				else
					dispbox(thdc,i,1);
			}
			dispsepa(thdc,i);
		}
	}
	if( framey2 > 0 )	/* 多目的ﾊﾞｰが存在する */
		dispmmm(-1,"");
}

INT32 finditem(flag,x,y)	/* ﾏｳｽ位置がﾂｰﾙﾊﾞｰ内ｱｲﾃﾑ上にあるかどうか調べる */
INT32 flag;
INT32 x;
INT32 y;
{
	INT32 i,j,k,l,x1,x2,x3,y1,y2;

	if( flag == 0 ) {	/* ﾌﾚｰﾑｳｨﾝﾄﾞｳ上の位置 */
		for( i = 0 ; i < nrbnrow ; i++ ) {
			if( y >= rbnrow[i].y0 && y < rbnrow[i].y1 )
				break;
		}
		if( i >= nrbnrow ) {	/* ﾂｰﾙﾊﾞｰ上ではない */
			if( messp == 0 && y >= framey1 && y < (framey1+framey2) ) {	/* 多目的ﾊﾞｰ上 */
				if( chkminlist() ) {	/* ﾘｽﾄｳｨﾝﾄﾞｳ最小化中→復元ﾎﾞﾀﾝあり */
					x1 = LEFTBTNCXL;
					x2 = LEFTTABCX2-LEFTTABCX1;
					x3 = LEFTTABCX2;
				}
				else {			/* 復元ﾎﾞﾀﾝなし(ｽｸﾛｰﾙﾎﾞﾀﾝのみ) */
					x1 = x2 = 0;
					x3 = LEFTTABCX1;
				}
				if( x >= x3 && x < framex0 ) {
					for( i = ntabfx0 ; i < ntabfx ; i++ ) {
						j = tabx0[i];
						l = tabfx[i];
						k = j+(l&0x0000ffff);
						y1 = getbarypos((l>>16)&0x000f);
						y2 = y1+framey6;
						if( y >= y1 && y < (y2+1) && x >= j && x < k ) {
							if( l&0x20000000 ) {	/* ｶﾚﾝﾄﾌｧｲﾙのｳｨﾝﾄﾞｳのﾀｸﾞ */
								if( x >= (k-2-14) )
									i = ntabfx;
							}
							return(2000+i);
						}
					}
					return(-1);
				}
				else if( y >= framey5 && y < (framey5+framey3) ) {
					if( x >= 0 && x < x1 )
						return(1002);	/* ﾘｽﾄｳｨﾝﾄﾞｳ復元ﾎﾞﾀﾝ */
					else if( x >= x2 && x < (x2+LEFTBTNCX) )
						return(1000);	/* ←ｽｸﾛｰﾙﾎﾞﾀﾝ */
					else if( x >= (x2+LEFTBTNCX) && x < (x2+LEFTBTNCX+LEFTBTNCX) )
						return(1001);	/* →ｽｸﾛｰﾙﾎﾞﾀﾝ */
				}
			}
			return(-1);	/* ﾏｳｽはｱｲﾃﾑ上にない */
		}
		for( j = 0 ; j < nrbnitem && rbnitem[j].row < i ; j++ ) ;
		for( ; j < nrbnitem ; j++ ) {
			if( i < rbnitem[j].row )
				return(-1);	/* ﾏｳｽはｱｲﾃﾑ上にない */
			if( x < rbnitem[j].x0 )
				return(-1);	/* ﾏｳｽはｱｲﾃﾑ上にない */
			if( x < rbnitem[j].x0+(INT32)rbnitem[j].cx ) {
				if( rbnitem[j].id == 22 ) {	/* 「検索」ﾎﾞｯｸｽ */
					findbtn = j;
#ifdef BOXINTOOLBAR
					if( hwndmldlg == NULL && pdlgdata == NULL && ap )
#else
					if( hwndmldlg == NULL && pdlgdata == NULL && ap && x >= (rbnitem[j].x0+(dlgfx*SELBOXTIT)) )
#endif
						return(1005);	/* 「検索」ﾎﾞｯｸｽ中の入力枠 */
				}
				return(j);	/* ﾂｰﾙﾊﾞｰ上のｱｲﾃﾑのID */
			}
		}
	}
	else if( flag == 1 ) {	/* 編集子ｳｨﾝﾄﾞｳ上の位置 */
		if( ap == NULL )
			return(-1);
		if( ap != mp )
			return(-1);
		if( y < 0 )
			return(-1);
		else if( y < mp->guidey ) {	/* ｶﾞｲﾄﾞﾗｲﾝ上 */
			if( x < xposwaku )
				return(1018);
			else if( x < xcodebtn )
				return(1019);
			else if( x < (xcodebtn+xcodesz) )
				return(1013);
			else if( x < (xnewlinebtn+xnewlinesz) )
				return(1015);	/* 入力改行コード切り替えボタン */
			else if( x >= mp->xmodebtn && x < (mp->xmodebtn+xmodesz1) )
				return(1010);
			else if( x >= (mp->xmodebtn+xmodesz1+8) && 
				x < (mp->xmodebtn+xmodesz1+8+xmodesz2) )
				return(1011);
			else if( x >= (mp->xmodebtn+xmodesz1+8+xmodesz2+8) && 
				x < (mp->xmodebtn+xmodesz1+8+xmodesz2+8+xmodesz3) )
				return(1012);
		}
		else if( y < (mp->guidey+mp->coly) && (mp->modeflgd&FLAG_COLG) ) {	/* 桁ｹﾞｰｼﾞ上 */
#ifdef MARKCOLUMN
			if( mp->bin2mode == 0 ) {	/* ﾃｷｽﾄﾓｰﾄﾞ */
				if( x >= (mp->startx-mp->x1) && x < (mp->startx+LEFTSPACE) )
					return(1014);
			}
#endif
		}
	}
	else if( flag == 2 ) {	/* ﾘｽﾄｳｨﾝﾄﾞｳ上の位置 */
		lstwinobjid = -1;
		if( hwndlstwin == NULL )
			return(-1);
		for( i = 0 ; i < lstwinobjs ; i++ ) {
			if( x >= lstwinx0[i] && x < (lstwinx0[i]+lstwincx[i]) && 
				y >= lstwiny0[i] && y < (lstwiny0[i]+lstwincy[i]) && 
				lstwinid[i] < 70 )
				break;
		}
		if( i >= lstwinobjs )
			return(-1);
		lstwinobjid = i;
		j = (INT32)lstwinid[i];
		if( j == 0 ) {		/* ﾘｽﾄﾎﾞｯｸｽ上 */
			k = lstwintop+((y-lstwiny0[i])/lstwincy1);
			if( k < lstwinnnn )
				return(3000+k);
			else
				return(-1);
		}
		else if( j == 4 )	/* ﾀｲﾄﾙﾊﾞｰ上 */
			return(1039);
		else if( j == 5 )	/* ﾀｲﾄﾙﾊﾞｰ上の「▼」ﾎﾞﾀﾝ */
			return(1028);
		else if( j == 6 )	/* ﾀｲﾄﾙﾊﾞｰ上の「X」ﾎﾞﾀﾝ */
			return(1029);
		else if( j == 7 ) {	/* 検索ﾎﾞｯｸｽ */
			if( x < (lstwinx0[i]+lstwintitcx) )
				return(-1);	/* 「検索」ﾌﾟﾛﾝﾌﾟﾄ上 */
			else
				return(1032);
		}
		else if( j == 8 )	/* ﾘｽﾄの←ｽｸﾛｰﾙﾎﾞﾀﾝ */
			return(1030);
		else if( j == 9 )	/* ﾘｽﾄの→ｽｸﾛｰﾙﾎﾞﾀﾝ */
			return(1031);
		else if( j == 20 ) {	/* ｺﾝﾎﾞﾎﾞｯｸｽ1(ｿｰﾄ方法) */
			if( x >= (lstwinx0[i]+lstwincx[i]-1-lstwindefcx) )
				return(1022);	/* ﾌﾟﾙﾀﾞｳﾝﾎﾞﾀﾝ上 */
			else
				return(1023);
		}
		else if( j == 21 ) {	/* ｺﾝﾎﾞﾎﾞｯｸｽ2(ﾌｫﾙﾀﾞ) */
			if( x >= (lstwinx0[i]+lstwincx[i]-1-lstwindefcx) )
				return(1024);	/* ﾌﾟﾙﾀﾞｳﾝﾎﾞﾀﾝ上 */
			else
				return(1025);
		}
		else if( j == 22 ) {	/* ｺﾝﾎﾞﾎﾞｯｸｽ3(ﾜｲﾙﾄﾞｶｰﾄﾞ) */
			if( x >= (lstwinx0[i]+lstwincx[i]-1-lstwindefcx) )
				return(1026);	/* ﾌﾟﾙﾀﾞｳﾝﾎﾞﾀﾝ上 */
			else
				return(1027);
		}
		else if( j >= 40 && j < 60 ) {	/* 機能ﾎﾞﾀﾝ */
			return(1040+j-40);
		}
		else
			return(-1);
	}
	return(-1);	/* ﾏｳｽはｱｲﾃﾑ上にない */
}

void tabdragmark(flag,id)	/* 多目的ﾊﾞｰ上のﾀﾌﾞのﾄﾞﾗｯｸﾞ＆ﾄﾞﾛｯﾌﾟ中に、ﾄﾞﾗｯｸﾞ位置ﾏｰｸを表示/消去する */
INT32 flag;	/* 0=位置ﾏｰｸを消す  1=ﾄﾞﾗｯｸﾞ位置ﾏｰｸを表示する  2=ﾄﾞﾛｯﾌﾟ位置ﾏｰｸを表示する */
INT32 id;	/* ﾀﾌﾞのID */
{
	INT32 i,data,x,xw,y;
	BYTE mflag;
	HDC thdc;
	HFONT hfontold;
	HPEN hpen,hpenold;
	HBRUSH hbold;

	/* ﾀﾌﾞ枠の表示位置を取得 */
	if( id < ntabfx0 || id >= ntabfx )	/* 指定のﾀﾌﾞは画面内にない */
		return;
	x = tabx0[id];
	data = tabfx[id];
	xw = (data&0x0000ffff);
	y = getbarypos((data>>16)&0x000f);
	i = ((data>>20)&0x00ff);
	/* ﾀﾌﾞの枠線だけを再表示 */
	if( flag == 0 )		/* 通常ﾀﾌﾞを表示 */
		mflag = 2;
	else if( flag == 1 )	/* 移動元ﾀﾌﾞを表示 */
		mflag = 3;
	else			/* 移動先ﾀﾌﾞを表示 */
		mflag = 4;
	thdc = GetDC(hfwnd);
	SetBkMode(thdc,TRANSPARENT);
	hfontold = SelectObject(thdc,hbalf);
	hpen = CreatePen(PS_SOLID,1,colortab[48]);
	hpenold = SelectObject(thdc,hpen);
	hbold = SelectObject(thdc,GetStockObject(NULL_BRUSH));	/* NULL_BRUSH=背景透過のﾌﾞﾗｼ */
	dispvtab(thdc,i,id,x,y,&mflag);
	SelectObject(thdc,hpenold);
	DeleteObject(hpen);
	SelectObject(thdc,hbold);
	SelectObject(thdc,hfontold);
	ReleaseDC(hfwnd,thdc);
}

INT32 btnintab(flag,id)	/* 多目的ﾊﾞｰ上の編集ﾌｧｲﾙ名ﾀﾌﾞ中にあるﾎﾞﾀﾝの表示 */
INT32 flag;	/* 0=通常状態のﾎﾞﾀﾝを表示  1=押下状態のﾎﾞﾀﾝを表示 */
INT32 id;	/* ﾎﾞﾀﾝのID */
{
	HDC thdc;
	INT32 i,j,x,xw,y,y5;

	if( messt < 20 )
		return(0);
	if( id < 2000 || id >= 3000 )
		return(0);
	id -= 2000;
	if( id == ntabfx ) {	/* ｶﾚﾝﾄﾌｧｲﾙのﾀﾌﾞ上の「×」ﾎﾞﾀﾝ */
		for( i = ntabfx0 ; i < ntabfx ; i++ ) {
			if( tabfx[i]&0x20000000 )
				break;
		}
		if( i < ntabfx ) {
			j = 1;
			goto dispbtn;
		}
	}
	else if( id >= ntabfx0 && id < ntabfx ) {
		if( ((tabfx[id]>>20)&0x00ff) == MAXTEXT ) {	/* 新規作成ﾀﾌﾞ */
			i = id;
			j = 2;
			dispbtn:
			x = tabx0[i];
			xw = (tabfx[i]&0x0000ffff);
			y = getbarypos((tabfx[i]>>16)&0x000f);
			y5 = y+1+((framey6-2-14)/2);	/* 上部の隙間の計算はﾎﾞﾀﾝの高さを14ﾋﾟｸｾﾙと見なして行なう */
			thdc = GetDC(hfwnd);
			if( j == 1 ) {		/* ｶﾚﾝﾄﾌｧｲﾙのﾀﾌﾞ上の「×」ﾎﾞﾀﾝ */
				dispgenbtn(thdc,NULL,NULL,x+xw-1-1-2-14,y5,14,13,
					COLORCLOSEBTNFOR,COLORCLOSEBTNBAK,COLORBTNBORDER3,COLORBTNBORDER3,(flag==1)?NULL:("\x0a"));
			}
			else {			/* 新規作成ﾀﾌﾞ */
				if( flag == 0 )
					gradationrect(thdc,x+1,y+1,x+xw-2,y+framey6-1,4,colortab[19]);
				dispgenbtn(thdc,NULL,NULL,x+1+2,y5,14,14,colortab[20],
						(0xff000000|colortab[19]),0,0,(flag==1)?NULL:("\x11"));
			}
			ReleaseDC(hfwnd,thdc);
			return(j);
		}
	}
	return(0);
}

INT32 getlowfunc(id)	/* 多目的ﾊﾞｰのﾌｧﾝｸｼｮﾝｷｰ/編集ﾌｧｲﾙ名のﾃﾞｰﾀIDを返す */
INT32 id;	/* ﾏｳｽｶｰｿﾙ位置のID(2000～) */
{
	id -= 2000;
	if( messt < 20 ) {	/* ﾌｧﾝｸｼｮﾝｷｰ表示 */
		id += messt;
		if( id < DISPFUNC ) {
			if( meskk == 1 )
				id += 16;
			else if( meskk == 2 )
				id += (16+16);
			else if( meskk == 3 )
				id += (16+16+16+26+10+10+10+4+6+10+4);
			else if( meskk == 4 )
				id += (16+16+16+26+10+10+10+4+6+10+4+16+10);
			return(id);
		}
		return(-1);
	}
	else {			/* 編集ﾌｧｲﾙ名表示 */
		if( (!(yyyymode&XXXX_SDILOWG)) && (sssmode&SYS_UNIQ) ) {/* SDIﾓｰﾄﾞで編集ﾌｧｲﾙ名表示なし */
		}
		else {			/* MDIﾓｰﾄﾞ または SDIﾓｰﾄﾞで編集ﾌｧｲﾙ名表示中 */
			if( id < ntabfx )
				id = ((tabfx[id]>>20)&0x00ff);	/* id=0～MAXTEXT-1 or MAXTEXT */
			else			/* ｶﾚﾝﾄﾌｧｲﾙのﾀﾌﾞ中の「×」ﾎﾞﾀﾝ上 */
				id = (MAXTEXT+1);
			return(1000+id);
		}
		return(-1);
	}
}

void dispkey()
{
	HDC thdc;

	if( keyxxx >= 0 ) {	/* 多目的ﾎﾞﾀﾝが表示されている */
		thdc = GetDC(hfwnd);
		dispbtn(thdc,keyxxx,0);
		ReleaseDC(hfwnd,thdc);
	}
}

void dispkey2()
{
	HDC thdc;

	if( keyxxx >= 0 ) {	/* 多目的ﾎﾞﾀﾝが表示されている */
		if( keyccc == (BYTE)key2flg )
			return;
		keyccc = (BYTE)key2flg;
		thdc = GetDC(hfwnd);
		dispbtn(thdc,keyxxx,0);
		ReleaseDC(hfwnd,thdc);
	}
}

void dispkey20()
{
	HDC thdc;

	if( immok ) {
		ImmSetOpenStatus(ImmGetContext(hfwnd),immstat);
      	}
	immok = FALSE;
	if( keyxxx >= 0 ) {	/* 多目的ﾎﾞﾀﾝが表示されている */
		thdc = GetDC(hfwnd);
		dispbtn(thdc,keyxxx,0);
		ReleaseDC(hfwnd,thdc);
	}
}

void dispins()		/* 挿入/上書きﾎﾞﾀﾝ(特殊ﾎﾞﾀﾝ)の表示切り替え */
{
	HDC thdc;

	if( insxxx >= 0  ) {	/* 挿入/上書きﾎﾞﾀﾝが表示されている */
		thdc = GetDC(hfwnd);
		dispbtn(thdc,insxxx,0);
		ReleaseDC(hfwnd,thdc);
	}
}

void dispkei()		/* 罫線種切り替えﾎﾞﾀﾝ(特殊ﾎﾞﾀﾝ)の表示切り替え */
{
	HDC thdc;

	if( keixxx >= 0 ) {	/* 罫線種切り替えﾎﾞﾀﾝが表示されている */
		thdc = GetDC(hfwnd);
		dispbtn(thdc,keixxx,0);
		ReleaseDC(hfwnd,thdc);
	}
}

void dispkmac()		/* ｷｰﾎﾞｰﾄﾞﾏｸﾛ定義ﾎﾞﾀﾝ(特殊ﾎﾞﾀﾝ)の表示切り替え */
{
	HDC thdc;

	if( recxxx >= 0 ) {	/* ｷｰﾎﾞｰﾄﾞﾏｸﾛ定義ﾎﾞﾀﾝが表示されている */
		thdc = GetDC(hfwnd);
		dispbtn(thdc,recxxx,0);
		ReleaseDC(hfwnd,thdc);
	}
}

void setupdflg(flag)	/* 変更ﾌﾗｸﾞの 1,2=ｾｯﾄ  0=ﾘｾｯﾄ */
INT32 flag;
{
	BYTE chgflg;

	chgflg = 0;
	if( flag ) {	/* 変更ﾌﾗｸﾞのｾｯﾄ */
		if( mp->upflg == 0 )
			chgflg = 1;
		mp->upflg = (BYTE)flag;
		if( mp->autoupflg < 1000000 )
			mp->autoupflg++;
	}
	else {		/* 変更ﾌﾗｸﾞのﾘｾｯﾄ */
		if( mp->upflg )
			chgflg = 1;
		mp->upflg = 0;
		mp->autoupflg = 0;
	}
	if( chgflg ) {	/* 多目的ﾊﾞｰの編集ﾌｧｲﾙ名表示の更新 */
		if( messp == 0 && framey2 > 0 && messt >= 20 && mesdd == -1 ) {
			mesdd = -4;
			dispmmm(0,"");
		}
		setwintxt();	/* ﾀｲﾄﾙﾊﾞｰの再表示 */
		listupdate(0);	/* ﾘｽﾄｳｨﾝﾄﾞｳ中のﾌｧｲﾙ履歴の再表示 */
	}
}

void refuncdd()		/* 最下行の編集ﾌｧｲﾙ名表示の更新 */
{
	if( messp == 0 && framey2 > 0 && messt >= 20 && mesdd == -1 ) {
		mesdd = -2;
		dispmmm(0,"");
	}
}

void dispwaitmess(id)	/* 多目的ﾊﾞｰ上に時間がかかる処理のﾒｯｾｰｼﾞを表示する */
INT32 id;	/* 0=ｼﾞｬﾝﾌﾟ  1=検索  2=切り取り/ｺﾋﾟｰ  3=貼り付け  4=折り返し桁位置の調整  5=巨大ﾌｧｲﾙの読み込み  6=UNDO処理 */
{
	INT32 i;
	BYTE mess[256],buff[64],buff1[200];

	if( id < 10 ) {	/* 処理中ﾒｯｾｰｼﾞを表示 */
		if( id == 6 )
			i = 322;
		else
			i = 1462;
	}
	else {		/* 処理の中止ﾒｯｾｰｼﾞを表示 */
		id -= 10;
		i = 1463;	/* ～を中止しました。*/
	}
	getpartstr(1424,id,buff,64);
	LoadString(hinst,i,buff1,200);
	wsprintf(mess,buff1,buff);
	messnextx = messnexty = 0;
	dispmmm(1,mess);
	if( id < 10 )
		keyflush();
}

void dispprog(num)	/* 多目的ﾊﾞｰ上のﾒｯｾｰｼﾞの最後に進捗状態( % 表示)を表示する */
INT32 num;	/* % 値 */
{
	INT32 len;
	HFONT hfold;
	HDC thdc;
	BYTE buff[16];

	if( messnextx || messnexty ) {
		thdc = GetDC(hfwnd);
		SetBkColor(thdc,colortab[19]);
		SetTextColor(thdc,colortab[20]);
		hfold = SelectObject(thdc,hbalf);
		len = wsprintf(buff,"  %2d %% ",num);
		TextOut(thdc,messnextx,messnexty,buff,len);
		SelectObject(thdc,hfold);
		ReleaseDC(hfwnd,thdc);
	}
}

INT32 kana2to1(d,s)	/* 全角文字列を半角文字列に変換する */
BYTE *d;
BYTE *s;
{
	BYTE *p,c1,c2;

	for( p = d ; *s ; ) {
		if( ctypej[*s]&CKANJI1 ) {
			c1 = *s++;
			c2 = *s++;
			if( (c1==0x81 && (c2==0x41 || c2==0x42 || c2==0x45 || c2==0x5b || c2==0x75 || c2==0x76)) || (c1==0x83 && c2>=0x40 && c2<=0x96) ) {
				p += zen2hankana(p,c1,c2);
			}
			else {
				*p++ = c1;
				*p++ = c2;
			}
		}
		else
			*p++ = *s++;
	}
	*p = '\0';
	return((INT32)(p-d));
}

INT32 barfuncstr(id,buff)	/* 多目的ﾊﾞｰに表示するﾌｧﾝｸｼｮﾝｷｰ文字列を取得する */
INT32 id;	/* ﾌｧﾝｸｼｮﾝｷｰの機能番号 */
BYTE *buff;	/* ﾌｧﾝｸｼｮﾝｷｰ文字列を返すﾊﾞｯﾌｧ */
{
	INT32 i,j;
	BYTE *p,*q,c1,c2,buff1[64];

	i = getfuncstr(id,0x0000,buff,NULL,NULL);
	if( i <= 18 )	/* ﾌｧﾝｸｼｮﾝｷｰ文字列が18ﾊﾞｲﾄ以内 */
		return(i);
	/* ﾌｧﾝｸｼｮﾝｷｰ文字列が長い場合 */
	for( p=buff,q=buff1,j=0 ; *p ; ) {
		if( ctypesjis[*p]&CKANJI1 ) {
			c1 = *p++;
			c2 = *p++;
			if( (c1==0x81 && (c2==0x41 || c2==0x42 || c2==0x45 || c2==0x5b || c2==0x75 || c2==0x76)) || (c1==0x83 && c2>=0x40 && c2<=0x96) ) {
				j++;
				q += zen2hankana(q,c1,c2);
			}
			else {
				*q++ = c1;
				*q++ = c2;
			}
		}
		else if( ctypesjis[*p]&CASCII )
			*q++ = *p++;
		else
			break;
	}
	*q = '\0';
	if( j >= 2 ) {	/* 全角ｶﾅが2文字以上あった */
		for( p=buff1,q=buff ; *p ; )
			*q++ = *p++;
		*q = '\0';
		return((INT32)(q-buff));
	}
	return(i);
}

void dispmmm(id,mess)		/* 多目的ﾊﾞｰにﾒｯｾｰｼﾞを表示する */
INT32 id;	/* ﾒｯｾｰｼﾞ優先順位						*/
		/*  -4=ﾏｸﾛｺﾏﾝﾄﾞの実行終了時の処理				*/
		/*  -3=ﾒｯｾｰｼﾞｽﾀｯｸの初期化					*/
		/*  -2=ﾒｯｾｰｼﾞ表示領域のｸﾘｱ					*/
		/*  -1=現在のﾒｯｾｰｼﾞを再表示					*/
		/*   0=編集ﾌｧｲﾙ名/ﾌｧﾝｸｼｮﾝｷｰ表示(*messは必ずﾇﾙ文字列) 		*/
		/*   1=ﾒﾆｭｰ/ﾎﾞﾀﾝの詳細表示,ｺﾝﾊﾟｲﾙｴﾗｰ表示,検索失敗ﾒｯｾｰｼﾞ		*/
		/*    （編集ﾌｧｲﾙ名/ﾌｧﾝｸｼｮﾝｷｰ表示をこの優先順位(1)で表示させたい	*/
		/*      場合(*messにﾇﾙ文字列を指定)にも使用できる）		*/
		/*   2=message()関数による表示					*/
		/*   3=ｼﾝｸﾞﾙｽﾃｯﾌﾟ実行時のｿｰｽｺｰﾄﾞ表示,bp()関数による表示		*/
		/* 編集ﾌｧｲﾙ名/ﾌｧﾝｸｼｮﾝｷｰ表示に戻すには、以下の2通りの方法	*/
		/*   dispmmm(1,"") --- 一般ﾒｯｾｰｼﾞ表示中でも戻すことが可能	*/
		/*   dispmmm(0,"") --- 一般ﾒｯｾｰｼﾞ表示中には無視されるが、	*/
		/*                   mesdd == -2 なら強制的に戻される		*/
BYTE *mess;	/* 表示するﾒｯｾｰｼﾞ(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) --- ﾇﾙ文字列なら表示の消去	*/
{
	HDC thdc;
	RECT rc;
	HFONT hfold;
	SIZE sz;
	HPEN hpen,hpenold;
	HBRUSH hbold;
	INT32 bkmode,i,i0,i1,j,k,l,m,n,ntabfxx;
	INT32 x,x1,x2,xw,y,y1,y2,y3,y4,y5,y6,y7,yid;
	INT32 idsorted[MAXTEXT+4];
	BYTE flag,mflag,crrtab,*p,buff[PATHSIZE+256];
	WCHAR wbuff[PATHSIZE+256];

/* mesdd=現在の最下行の表示状態						*/
/*      -10:表示状態は不定						*/
/* -4,-3,-2:編集ﾌｧｲﾙ名/ﾌｧﾝｸｼｮﾝｷｰを強制的に再表示させるために外部で指定	*/
/*       -1:編集ﾌｧｲﾙ名を表示中						*/
/*     0～4:ﾌｧﾝｸｼｮﾝｷｰを表示中(meskkと同じ値)				*/
/*       16:ﾒｯｾｰｼﾞ文字列を表示中					*/
	if( framey2 == 0 && id >= 2 && *mess ) {	/* ﾏｸﾛｺﾏﾝﾄﾞによる多目的ﾊﾞｰの強制表示 */
		for( j = 0 ; j < 4 ; j++ ) {
			ppmac->idmessp[j] = 0;
			ppmac->strmessp[j][0] = '\0';
		}
		messp = 0;
		meskk = 0;
		mesdd = -10;
		messp++;
		ppmac->idmessp[messp] = (BYTE)id;
		movetxtf(ppmac->strmessp[messp],mess,300);
		oldmessid = ((exsysmode&EXSYS_2LINES)?2:1);
		exsysmode &= (~(EXSYS_NOFUNC|EXSYS_2LINES));	/* 強制的に多目的ﾊﾞｰを1行で表示とする */
		sysmode &= (~SYS_UPPERBAR);			/* 強制的に多目的ﾊﾞｰを下部に配置とする */
		messff = 1;		/* ﾏｸﾛｺﾏﾝﾄﾞにより強制的に多目的ﾊﾞｰを1行で下部に表示 */
		framey4 = 1;
		framey2 = framey6+1+1;	/* 多目的ﾊﾞｰ1行表示時の高さ */
		framey -= framey2;
		framey1 = frameyy+framey;
		framey5 = framey1;
		rc.left = 0;
		rc.right = framex0;
		rc.top = frameyy;
		rc.bottom = frameyy+framey+framey2;
		exlstgo(3);
		InvalidateRect(hfwnd,&rc,TRUE);
		return;
	}
	if( id == -4 ) {	/* 一時的に強制表示していた多目的ﾊﾞｰの表示を消す --- ﾏｸﾛｺﾏﾝﾄﾞ終了時など */
		if( messff ) {	/* 多目的ﾊﾞｰを一時的に強制表示していた場合 */
			messff = 0;
			if( framey2 > 0 ) {
				exsysmode |= EXSYS_NOFUNC;	/* 多目的ﾊﾞｰを非表示とする */
				oldmessid = 0;
				framey += framey2;
				framey4 = 0;
				framey2 = 0;
				rc.left = 0;
				rc.right = framex0;
				rc.top = frameyy;
				rc.bottom = frameyy+framey;
				exlstgo(3);
				InvalidateRect(hfwnd,&rc,TRUE);
				return;
			}
		}
		return;
	}
	else if( id == -3 ) {	/* ﾏｸﾛｺﾏﾝﾄﾞ終了時 */
		for( j = 0 ; j < 4 ; j++ ) {
			ppmac->idmessp[j] = 0;
			ppmac->strmessp[j][0] = '\0';
		}
		messp = 0;
		meskk = 0;
		mesdd = -2;
		flag = 1;
	}
	else if( id == -2 ) {	/* ﾒｯｾｰｼﾞ表示領域のｸﾘｱ */
		flag = 1;	/* 編集ﾌｧｲﾙ名/ﾌｧﾝｸｼｮﾝｷｰ表示 */
	}
	else if( id == -1 ) {	/* 現在のﾒｯｾｰｼﾞを再表示 */
		id = (INT32)ppmac->idmessp[messp];
		mesdd = -2;
		if( id == 0 )	/* 編集ﾌｧｲﾙ名/ﾌｧﾝｸｼｮﾝｷｰ表示 */
			flag = 1;
		else		/* ﾒｯｾｰｼﾞ表示 */
			flag = 0;
	}
	else {			/* 通常のﾒｯｾｰｼﾞ表示 */
#ifdef EXTBOXEDIT
		if( pbox ) {	/* 箱型編集ﾓｰﾄﾞ中 */
			if( id == 1 )	/* 箱型編集ﾓｰﾄﾞ終了ﾒｯｾｰｼﾞの優先順位が2なので、それよりも高い優先順位とする */
				id = 3;
		}
#endif
		if( id < ppmac->idmessp[messp] ) {	/* 現在のﾒｯｾｰｼﾞより優先順位が低い */
			if( *mess || id == 0 )
				return;
			for( i = 1 ; i < messp ; i++ ) {
				if( id == ppmac->idmessp[i] ) {
					for( j = i ; j < messp ; j++ ) {
						ppmac->idmessp[j] = ppmac->idmessp[j+1];
						movetxtf(ppmac->strmessp[j],ppmac->strmessp[j+1],300);
					}
					messp--;
					break;
				}
			}
			return;
		}
		else if( id == ppmac->idmessp[messp] ) {/* 現在のﾒｯｾｰｼﾞと同じ優先順位 */
			if( *mess )
				movetxtf(ppmac->strmessp[messp],mess,300);
			else if( messp > 0 && id > 0 )
				id = ppmac->idmessp[--messp];
			else
				id = 0;
		}
		else {					/* 現在のﾒｯｾｰｼﾞより優先順位が高い */
			if( *mess == '\0' && id > 0 )
				return;
			if( messp >= 3 )	/* あり得ないｹｰｽ */
				MessageBeep(BEEPID2);
			else
				messp++;
			ppmac->idmessp[messp] = (BYTE)id;
			movetxtf(ppmac->strmessp[messp],mess,300);
		}
		if( id == 0 )	/* 編集ﾌｧｲﾙ名/ﾌｧﾝｸｼｮﾝｷｰ表示 */
			flag = 1;
		else		/* ﾒｯｾｰｼﾞ表示 */
			flag = 0;
	}
	if( framey2 == 0 ) {	/* ﾒｯｾｰｼﾞ表示領域がない(多目的ﾊﾞｰが非表示) */
		return;
		ppedit->ntabfxx = 0;
	}
	if( flag && messt < 20 && meskk == mesdd ) {	/* ﾌｧﾝｸｼｮﾝｷｰはすでに表示済 */
		ppedit->ntabfxx = 0;
		return;
	}
	if( (thdc=GetDC(hfwnd)) == NULL )
		return;
	rc.left = 0;
	rc.right = framex0;
	rc.top = framey1;
	rc.bottom = rc.top+framey2;
	hfold = NULL;
	if( flag == 0 ) {	/* 通常ﾒｯｾｰｼﾞの表示(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
		FillRect(thdc,&rc,hbrush6);
		for( i=0,p=ppmac->strmessp[messp] ; *p && *p != 0xff ; p++ ) {
			if( i < 290 && *p != 0x09 )
				buff[i++] = *p;
		}
		buff[i] = '\0';
		if( i > 0 ) {
			SetTextColor(thdc,colortab[20]);
			bkmode = SetBkMode(thdc,TRANSPARENT);
			l = 8;
			hfold = SelectObject(thdc,hbalf);
			j = ((framey6+1+1-balfy)/2);
			if( j < 0 )
				j = 0;
			i = exsjistounicode(buff,wbuff);
			TextOutW(thdc,l,framey1+j,wbuff,i);
			GetTextExtentPoint32W(thdc,wbuff,i,&sz);
			messnextx = l+sz.cx;
			messnexty = framey1+j;
			SetBkMode(thdc,bkmode);
		}
		mesdd = 16;
	}
	else {		/* 編集ﾌｧｲﾙ名の表示(拡張ｼﾌﾄJISﾌｫｰﾏｯﾄ)/ﾌｧﾝｸｼｮﾝｷｰ表示(ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
		messerr = 0;	/* 検索失敗ﾒｯｾｰｼﾞは表示してない */
		if( chkminlist() ) {	/* ﾘｽﾄｳｨﾝﾄﾞｳ最小化中 */
			x1 = LEFTTABCX2-LEFTTABCX1;
			x2 = LEFTTABCX2;
		}
		else {
			x1 = 0;
			x2 = LEFTTABCX1;
		}
		if( mesdd <= -3 )	/* 最下行の回転/変更ﾌﾗｸﾞの変更 の場合 */
			rc.left = x2-1;
		gradationrect(thdc,rc.left,rc.top,rc.right,rc.bottom,0x0100|2,colortab[22]);
		yid = 0;
		x = x2;
		y = getbarypos(yid);
		y1 = y+framey6;
		if( mesdd <= -3 ) ;	/* 最下行回転/変更ﾌﾗｸﾞの変更 の場合 */
		else {
			if( chkminlist() ) {	/* ﾘｽﾄｳｨﾝﾄﾞｳ最小化中 */
				dispgenbtn(thdc,NULL,hbrush6,0,framey5,LEFTBTNCXL,framey3,
					colortab[20],colortab[19],COLORBTNBORDER1,COLORBTNBORDER2,"\x08");
			}
			dispgenbtn(thdc,NULL,hbrush6,x1,framey5,LEFTBTNCX,framey3,
				colortab[20],0xfe000000|colortab[19],COLORBTNBORDER1,COLORBTNBORDER2,"\x02");
			dispgenbtn(thdc,NULL,hbrush6,x1+LEFTBTNCX,framey5,LEFTBTNCX,framey3,
				colortab[20],0xfe000000|colortab[19],COLORBTNBORDER1,COLORBTNBORDER2,"\x03");
		}
		if( (!(yyyymode&XXXX_SDILOWG)) && messt >= 20 && (sssmode&SYS_UNIQ) ) {	/* SDIﾓｰﾄﾞで編集ﾌｧｲﾙ名表示なし */
			if( framey4 >= 2 )
				PostMessage(hfwnd,WM_COMMAND,IDS_VBARDEC,0);
			mesdd = -1;
			ppedit->ntabfxx = 0;
			goto endmmm;
		}
		bkmode = SetBkMode(thdc,TRANSPARENT);
		hfold = SelectObject(thdc,hbalf);
		if( messt < 20 ) {	/* ﾌｧﾝｸｼｮﾝｷｰ表示 */
			if( sysmode&SYS_UPPERBAR ) {
				y2 = y+1;
				y3 = y1;
				y4 = y1-1;
				y5 = y;
				y6 = y-1;
			}
			else {
				y2 = y;
				y3 = y1-1;
				y4 = y;
				y5 = y1-1;
				y6 = y1;
			}
			if( meskk == 0 ) {	/* F1～ F12 */
				i0 = 0;
				i1 = 0;
			}
			else if( meskk == 1 ) {	/* Shift+F1～Shift+F12 */
				i0 = 16;
				i1 = 16;
			}
			else if( meskk == 2 ) {	/* Ctrl+F1～Ctrl+F12 */
				i0 = 16+16;
				i1 = 16+16;
			}
			else if( meskk == 3 ) {	/* Alt+F1～Alt+F12 */
				i0 = 16+16+16+26+10+10+10+4+6+10+4;
				i1 = 16+16+16;
			}
			else {			/* Ctrl+Shift+F1～Ctrl+Shift+12 */
				i0 = 16+16+16+26+10+10+10+4+6+10+4+16+10;
				i1 = 16+16+16+16;
			}
			xw = (balfx*22);
			for( i = 0 ; i < messt ; i++ )
				tabfx[i] = ((i<<20)|0x10000000);	/* 0x10000000=ﾌｧﾝｸｼｮﾝｷｰのﾀｸﾞ */
			ntabfx0 = i;		/* ntabfx0=messt */
			for( ; i < DISPFUNC ; i++ ) {
				j = 0;
				if( i < 9 ) {
					buff[j++] = 'F';
					buff[j++] = '1'+i;
				}
				else if( i < 12 ) {
					buff[j++] = 'F';
					buff[j++] = '1';
					buff[j++] = '0'+(i-9);
				}
				else {
					buff[j++] = ' ';
					buff[j++] = ' ';
					buff[j++] = ' ';
				}
				k = keydef[i0+i];
				dspfuncfunc[i] = k;
				m = 0;
				if( ppmac->fkeystr[i1+i][0] ) {	/* ﾕｰｻﾞｰ指定の表記が存在 */
					j += fstrcpy(&buff[j],ppmac->fkeystr[i1+i]);
					m++;
				}
				if( k < 0 ) {			/* 使用不可能なｷｰ */
					dspfuncgray[i] = 1;
					if( m == 0 )
						j += LoadString(hinst,1025,&buff[j],32);
				}
				else if( ( k > 0 && k < 250 ) || ( k >= ID_EXFUNC && k <= ID_FNCLAST ) || ( k >= ID_FNC2FIRST && k <= ID_FNC2LAST ) ) {/* 一般機能番号 */
					if( getmfs(k) == MFS_GRAYED )
						dspfuncgray[i] = 1;
					else
						dspfuncgray[i] = 0;
					if( m == 0 )
						j += barfuncstr(k,&buff[j]);
				}
				else {
					dspfuncgray[i] = 0;
					if( m == 0 )
						j += barfuncstr(k,&buff[j]);
				}
				if( (x+xw) >= framex0 ) {
					if( (++yid) >= framey4 ) {
						if( (exsysmode&EXSYS_2LINES) && framey4 < 2 )
							PostMessage(hfwnd,WM_COMMAND,IDS_VBARINC,0);
						break;
					}
					x = x2;
					y = getbarypos(yid);
					y1 = y+framey6;
					if( sysmode&SYS_UPPERBAR ) {
						y2 = y+1;
						y3 = y1;
						y4 = y1-1;
						y5 = y;
						y6 = y-1;
					}
					else {
						y2 = y;
						y3 = y1-1;
						y4 = y;
						y5 = y1-1;
						y6 = y1;
					}
				}
				rc.left = x+1;
				rc.right = x+xw-1;
				rc.top = y2;
				rc.bottom = y3;
				FillRect(thdc,&rc,hbrush6);
				if( dspfuncgray[i] == 0 ) {	/* 有効な機能のﾎﾞﾀﾝ */
					SetBkMode(thdc,OPAQUE);
					SetTextColor(thdc,colortab[20]);
					SetBkColor(thdc,colortab[50]);
				}
				else {				/* 無効な機能のﾎﾞﾀﾝ */
					SetBkMode(thdc,TRANSPARENT);
					SetTextColor(thdc,colortab[49]);
				}
				if( i < 9 )	/* F1～F9 */
					k = 2;
				else		/* F10～F12 */
					k = 3;
				y7 = ((framey6-balfy)/2);
				TextOut(thdc,rc.left+1,rc.top+y7,buff,k);
				if( (j=j-k) > 0 ) {
					SetBkMode(thdc,TRANSPARENT);
					SetTextColor(thdc,colortab[20]);
					ExtTextOut(thdc,rc.left+(balfx*k)+4,rc.top+y7,ETO_CLIPPED,&rc,&buff[k],j,NULL);
				}
				SelectObject(thdc,GetStockObject(WHITE_PEN));
				MoveToEx(thdc,x,y4,NULL);
				LineTo(thdc,x,y5);
				LineTo(thdc,x+xw,y5);
				SelectObject(thdc,GetStockObject(BLACK_PEN));
				if( x == x2 ) {		/* 左端のﾀﾌﾞ */
					MoveToEx(thdc,x-1,y4,NULL);
					LineTo(thdc,x-1,y6);
				}
				MoveToEx(thdc,x-1,y6,NULL);
				LineTo(thdc,x+xw,y6);
				MoveToEx(thdc,x+xw-1,y4,NULL);
				LineTo(thdc,x+xw-1,y6);
				tabx0[i] = x;
				tabfx[i] = (xw|(yid<<16)|(i<<20)|0x10000000);	/* 0x10000000=ﾌｧﾝｸｼｮﾝｷｰのﾀｸﾞ */
				x += xw;
			}
			ntabfx = i;
			for( ; i < DISPFUNC ; i++ )
				tabfx[i] = ((i<<20)|0x10000000);	/* 0x10000000=ﾌｧﾝｸｼｮﾝｷｰのﾀｸﾞ */
			ppedit->ntabfxx = 0;
			mesdd = meskk;
			if( (yid+1) < framey4 && (exsysmode&EXSYS_2LINES) )
				PostMessage(hfwnd,WM_COMMAND,IDS_VBARDEC,0);
		}
		else {		/* 編集中のﾌｧｲﾙ名表示(messt>=20) */
			hpen = CreatePen(PS_SOLID,1,colortab[48]);
			hpenold = SelectObject(thdc,hpen);
			hbold = SelectObject(thdc,GetStockObject(NULL_BRUSH));	/* NULL_BRUSH=背景透過のﾌﾞﾗｼ */
			ntabfxx = sortvbar(vbarsort,idsorted);
			k = messt-20;
			if( k >= ntabfxx ) {
				k = ntabfxx-2;
				if( k < 0 )
					k = 0;
				messt = k+20;
			}
			godisptab:
			for( n = 0 ; n < k ; n++ ) {
				i = idsorted[n];
				tabfx[n] = (i<<20);
			}
			ntabfx0 = n;	/* ntabfx0=messt-20(横ｽｸﾛｰﾙして見えない部分のﾀﾌﾞの数) */
			crrtab = 0;
			for( ; n < ntabfxx ; ) {
				i = idsorted[n];
				if( x == x2 )		/* 左端のﾀﾌﾞ */
					mflag = 1;
				else			/* 左端以外のﾀﾌﾞ */
					mflag = 0;
				xw = dispvtab(thdc,i,n,x,y,&mflag);
				if( xw < 0 ) {		/* 現在のﾀﾌﾞ行に入り切らない */
					xw = 0-xw;
					if( (yid+1) >= framey4 ) {
						if( exsysmode&EXSYS_2LINES )
							PostMessage(hfwnd,WM_COMMAND,IDS_VBARINC,0);
						break;
					}
					/* 次の行の左端位置へ */
					x = x2;
					y = getbarypos(++yid);
					continue;
				}
				/* 実際に表示したﾀﾌﾞの情報を記録する */
				tabx0[n] = x;
				tabfx[n] = (xw|(yid<<16)|(i<<20));
				if( mflag&0x20 ) {	/* ｶﾚﾝﾄﾌｧｲﾙ */
					tabfx[n] |= 0x20000000;
					crrtab = 1;
				}
				if( mflag&0x40 )	/* 変更操作が禁止されたﾌｧｲﾙ */
					tabfx[n] |= 0x40000000;
				/* 次のﾀﾌﾞへ */
				n++;
				x += xw;
			}
			/* 編集ﾌｧｲﾙ名の1行表示時に、ｶﾚﾝﾄﾌｧｲﾙのﾀﾌﾞが表示されないｹｰｽへの対処 */
			if( crrtab == 0 && (!(exsysmode&EXSYS_2LINES)) && ap && mesrt == 0 ) {
				for( j = 0 ; j < k ; j++ ) {
					if( &ppedit->etext[idsorted[j]] == ap )
						break;
				}
				if( j < k ) {
					k = j;
					redisptab:
					messt = k+20;
					x = x2;
					rc.left = x2-1;
					gradationrect(thdc,rc.left,rc.top,rc.right,rc.bottom,0x0100|2,colortab[22]);
					goto godisptab;
				}
				for( k++ ; k < ntabfxx ; k++ ) {
					x = x2;
					crrtab = 0;
					for( j = k ; j < ntabfxx ; j++ ) {
						if( x == x2 )		/* 左端のﾀﾌﾞ */
							mflag = 11;
						else			/* 左端以外のﾀﾌﾞ */
							mflag = 10;
						xw = dispvtab(thdc,idsorted[j],j,x,y,&mflag);
						if( xw < 0 )
							break;
						if( mflag&0x20 ) {	/* ｶﾚﾝﾄﾌｧｲﾙ */
							crrtab = 1;
							break;
						}
						x += xw;
					}
					if( crrtab )
						break;
				}
				if( k < ntabfxx )
					goto redisptab;
			}
			ntabfx = n;	/* [ntabfx0]～[ntabfx-1] までのﾀﾌﾞが画面に表示される */
			for( ; n < ntabfxx ; n++ ) {
				i = idsorted[n];
				tabfx[n] = (i<<20);
			}
			ppedit->ntabfxx = ntabfxx;
			mesdd = -1;
			SelectObject(thdc,hpenold);
			DeleteObject(hpen);
			SelectObject(thdc,hbold);
			if( (yid+1) < framey4 && (exsysmode&EXSYS_2LINES) )
				PostMessage(hfwnd,WM_COMMAND,IDS_VBARDEC,0);
		}
		SetBkMode(thdc,bkmode);
	}
	endmmm:
	if( hfold )
		SelectObject(thdc,hfold);
	ReleaseDC(hfwnd,thdc);
}

INT32 dlgmess(hdlg,id,mbflag)	/* ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽ中からﾒｯｾｰｼﾞﾎﾞｯｸｽを表示する */
HWND hdlg;
INT32 id;
DWORD mbflag;
{
	INT32 i;
	BYTE title[80],mess[512];

	GetWindowText(hdlg,title,80);
	LoadString(hinst,id,mess,500);
	i = messageboxO(hdlg,mess,title,mbflag);
	return(i);
}

INT32 dispmess(id)
INT32 id;
{
	BYTE strms[512];

	if( kinmess == 0 ) {
		LoadString(hinst,id,strms,500);
		messageboxO(hfwnd,strms,miwvermes,MB_OK|MB_ICONINFORMATION);
	}
	if( kmacexe >= 2 && id > 100 )	/* ｷｰﾎﾞｰﾄﾞﾏｸﾛの実行中、ｴﾗｰﾒｯｾｰｼﾞ */
		kmacexe = 0;
	return(id);
}

INT32 dispmess0(hwnd,id,mess)
HWND hwnd;
INT32 id;
BYTE *mess;
{
	BYTE strms[160],buff[1024];

	LoadString(hinst,id,strms,160);
	if( mess ) {
		wsprintf(buff,strms,mess);
		messageboxM(hwnd,buff,miwvermes,MB_OK|MB_ICONINFORMATION);
	}
	else {
		messageboxO(hwnd,strms,miwvermes,MB_OK|MB_ICONINFORMATION);
	}
	return(0);
}

INT32 dispmess1(id,num,str)
INT32 id;
LONG num;
BYTE *str;
{
	BYTE strms[512],buff[5120];

	if( kinmess == 0 ) {
		LoadString(hinst,id,strms,500);
		if( str )
			wsprintf(buff,strms,str);
		else
			wsprintf(buff,strms,num);
		messageboxM(hfwnd,buff,miwvermes,MB_OK|MB_ICONINFORMATION);
	}
	if( kmacexe >= 2 && id > 100 )
		kmacexe = 0;
	return(id);
}

INT32 dispmess2(id,str1,str2)	/* 2つのﾌｧｲﾙ名/ﾊﾟｽ名/ﾌｫﾙﾀﾞ名を含む情報表示用ﾒｯｾｰｼﾞﾎﾞｯｸｽ */
INT32 id;	/* 書式制御文字列のﾘｿｰｽID */
BYTE *str1;	/* ﾌｧｲﾙ名/ﾊﾟｽ名/ﾌｫﾙﾀﾞ名(その1) */
BYTE *str2;	/* ﾌｧｲﾙ名/ﾊﾟｽ名/ﾌｫﾙﾀﾞ名(その2) */
{
	BYTE buff[PATHSIZE+PATHSIZE+256];

	if( kinmess == 0 ) {
		*(INT32 *)&buff[0] = id;
		*(INT32 *)&buff[4] = (0x2000|0x0080|0x0000);
		fstrcpy(&buff[8],str1);
		fstrcpy(&buff[8+PATHSIZE],str2);
		dialogboxparamO(hinst,IDD_ERRORMES1,hfwnd,HistqueryDlg,(LPARAM)buff);
	}
	if( kmacexe >= 2 && id > 100 )
		kmacexe = 0;
	return(id);
}

INT32 dispmess3(str)	/* ﾏｸﾛｺﾏﾝﾄﾞのｺﾝﾊﾟｲﾙ時のｴﾗｰﾒｯｾｰｼﾞを表示する */
BYTE *str;
{
	if( framey2 == 0 ) {	/* ﾒｯｾｰｼﾞ表示領域がない */
		messageboxM(hfwnd,str,miwvermes,MB_OK|MB_ICONINFORMATION);
		return(0);
	}
	else {
		dispmmm(1,str);
		return(1);
	}
}

INT32 dispmesso()	/* ﾌｧｲﾙｵｰﾌﾟﾝ時のｴﾗｰﾒｯｾｰｼﾞを表示する */
{
	BYTE strms[512];

	if( kinmess == 0 ) {
		LoadString(hinst,opnerrid,strms,500);
		messageboxO(hfwnd,strms,miwvermes,MB_OK|MB_ICONSTOP);
	}
	if( kmacexe >= 2 )
		kmacexe = 0;
	return(opnerrid);
}

INT32 dispmesse(errid,str)	/* 検索文字列の指定ｴﾗｰをﾒｯｾｰｼﾞ表示する */
INT32 errid;	/*  -1=検索文字列の中間ｺｰﾄﾞへの変換ｴﾗｰ			*/
		/*  -2=ﾊﾞｲﾅﾘﾓｰﾄﾞでは検索不可能な文字列			*/
		/*  -3=正規表現検索(Pel互換)における量指定子の指定ｴﾗｰ	*/
		/* -10=ｸﾞﾛｰﾊﾞﾙ検索時の検索文字列のﾄｰﾀﾙの長さが長過ぎる	*/
BYTE *str;
{
	INT32 i,j;
	BYTE buff[MAXFINDSTRGREP+128];

	buff[0] = 0;		/* ﾀﾞｲｱﾛｸﾞﾎﾞｯｸｽのﾀｲﾌﾟを示す */
	i = 1;
	i += fstrcpy(&buff[i],str);	/* 検索文字列 */
	buff[i++] = '\0';
	buff[i++] = '\0';	/* 空行 */
	if( errid == -2 )
		j = 1;
	else if( errid == -3 )
		j = 3;
	else if( errid == -10 )
		j = 2;
	else
		j = 0;
	getpartstr(104,j,&buff[i],80);	/* 続きのﾒｯｾｰｼﾞ */
	dialogboxparamO(hinst,IDD_NOFIND,hfwnd,NofindDlg,(LPARAM)buff);
	return(1);
}

INT32 query1(hWnd,i)		/* ﾌﾚｰﾑｳｨﾝﾄﾞｳのｸﾛｰｽﾞ確認 */
HWND hWnd;
INT32 i;
{
	INT32 j;

	if( kmacexe >= 2 )	/* ｷｰﾎﾞｰﾄﾞﾏｸﾛ実行中 */
		return(IDNO);	/* 保存しない */
	j = dialogboxO(hinst,IDD_ENDQUERY,hfwnd,EndqueryDlg);
	if( sample ) {	/* 見本版として動作中 */
		if( j == IDYES || j == IDD_ENDQYES1 )
			j = IDNO;
	}
	return(j);
}

INT32 query2(hWnd)		/* ｾｯｼｮﾝ終了ﾒｯｾｰｼﾞの確認 */
HWND hWnd;
{
	BYTE strms[160];

	LoadString(hinst,35,strms,160);
	return(messageboxO(hWnd,strms,miwvermes,MB_YESNOCANCEL|MB_ICONEXCLAMATION));
}

INT32 query3(hWnd)		/* 編集ｳｨﾝﾄﾞｳのｸﾛｰｽﾞ確認 */
HWND hWnd;
{
	INT32 j;
	BYTE buff[PATHSIZE+256];

	if( kmacexe >= 2 || kinmess )	/* ｷｰﾎﾞｰﾄﾞﾏｸﾛ実行中 */
		return(IDNO);		/* 保存しない */
	*(INT32 *)&buff[0] = 31;
	*(INT32 *)&buff[4] = (0x4000|0x0200|0x0010|0x0000);
	fstrcpy(&buff[8],mp->outfile);
	j = dialogboxparamO(hinst,IDD_ERRORMES3,hWnd,HistqueryDlg,(LPARAM)buff);
	if( sample ) {
		if( j == IDYES )
			j = IDNO;
	}
	return(j);
}

INT32 query5(hWnd,path)		/* ﾃﾞｨｽｸ上に存在しないﾌｧｲﾙ名の履歴からの削除 */
HWND hWnd;
BYTE *path;
{
	BYTE buff[PATHSIZE+8];

	*(INT32 *)&buff[0] = 1368;
	*(INT32 *)&buff[4] = (0x4000|0x0020|0x0000);
	fstrcpy(&buff[8],path);
	return(dialogboxparamO(hinst,IDD_HISTQUERY,hWnd,HistqueryDlg,(LPARAM)buff));
}

INT32 querygrep(id)	/* ｸﾞﾛｰﾊﾞﾙ置換/ｸﾞﾛｰﾊﾞﾙ複数置換の中止/継続の問い合わせ */
INT32 id;		/* 保存ｴﾗｰｺｰﾄﾞ							*/
			/*   1=書き込みｴﾗｰ						*/
			/*   2=ﾎﾟｽﾄﾌﾟﾛｾｯｻ･ｴﾗｰ						*/
			/*   3=ﾘﾈｰﾑｴﾗｰ							*/
			/*   4=ﾊﾞｯｸｱﾌﾟﾌｧｲﾙ作成ｴﾗｰ					*/
			/*   5=無効ｺｰﾄﾞｴﾗｰ(ｴﾗｰ表示の必要ないｴﾗｰ)			*/
			/*   6=VirtualStoreへの書き込みｴﾗｰ(ｴﾗｰ表示の必要ないｴﾗｰ)	*/
			/*  10=書き込みｴﾗｰ(ﾎﾟｽﾄﾌﾟﾛｾｯｻ側ですでにｴﾗｰ表示済み)		*/
{
	BYTE buff[256];

	getpartstr(1018,(repsnnn==0?0:1),buff,256);
	if( messageboxO(hfwnd,buff,miwvermes,MB_YESNO|MB_ICONEXCLAMATION) == IDYES )
		return(id);	/* 中止=保存ｴﾗｰと見なす */
	else
		return(0);	/* 中止しない=保存ｴﾗｰはなしと見なす */
}

void saveerr(id)	/* 保存ｴﾗｰの報告 */
INT32 id;
{
	if( id == 5 || id == 6 || id == 10 )	/* すでに報告済みのｴﾗｰ */
		return;
	if( sssmode&SYS_UNIQ ) {	/* SDIﾓｰﾄﾞ */
		if( activeflg == 0 ) {	/* 自身はｶﾚﾝﾄｳｨﾝﾄﾞｳでない */
			SendMessage(hfwnd,WM_USER+190,0x00000010,0);
			SetForegroundWindow(hfwnd);
			PostMessage(hfwnd,WM_USER+193,0,(LPARAM)id);
			return;
		}
	}
	saveerr1(id,0);
}

void saveerr1(id,flag)	/* ﾌｧｲﾙ保存ｴﾗｰの報告 */
INT32 id;		/* ｴﾗｰID */
INT32 flag;		/* 0=通常の保存ｴﾗｰ  1=ｸﾞﾛｰﾊﾞﾙ置換時の保存ｴﾗｰ */
{
	INT32 i;
	BYTE strms[256],buff[PATHSIZE+256];

	if( flag ) {	/* ｸﾞﾛｰﾊﾞﾙ置換時の保存ｴﾗｰ */
		if( id == 5 || id == 6 || id == 10 )	/* すでに報告済みのｴﾗｰ */
			return;
		if( ap == NULL )
			return;
		if( ap != mp )
			setmp(ap);
	}
	if( id < 10 ) {
		if( kinmess == 0 ) {	/* ﾒｯｾｰｼﾞ表示は禁止されてない */
			if( id == 4 ) {		/* ﾊﾞｯｸｱｯﾌﾟﾌｧｲﾙの作成ｴﾗｰ */
				*(INT32 *)&buff[0] = 1099;
				*(INT32 *)&buff[4] = (flag|0x8000);
				fstrcpy(&buff[8],mp->outfile);
				goto errdlg1;
			}
			else if( id == 3 ) {	/* ﾘﾈｰﾑｴﾗｰ(ﾌｧｲﾙは保護されている) */
				*(INT32 *)&buff[0] = 353;
				*(INT32 *)&buff[4] = (0x8000|flag);
				fstrcpy(&buff[8],mp->outfile);
				errdlg1:
				dialogboxparamO(hinst,IDD_ERRORMES1,hfwnd,HistqueryDlg,(LPARAM)buff);
			}
			else if( id == 2 ) {	/* ﾎﾟｽﾄﾌﾟﾛｾｯｻ･ｴﾗｰ */
				LoadString(hinst,291,strms,250);
				i = wsprintf(buff,strms,mp->outdll);
				goto errdlg2;
			}
			else {			/* 書き込みｴﾗｰ */
				i = LoadString(hinst,43,buff,250);
				errdlg2:
				if( flag ) {	/* ｸﾞﾛｰﾊﾞﾙ置換時の保存ｴﾗｰ */
					buff[i++] = '\r';
					buff[i++] = '\n';
					getpartstr(24,2,&buff[i],80);
				}
				messageboxM(hfwnd,buff,miwvermes,MB_OK|MB_ICONEXCLAMATION);
			}
		}
	}
	if( flag == 0 ) {	/* 通常の保存ｴﾗｰ */
		if( kmacexe >= 2 )	/* ｷｰﾎﾞｰﾄﾞﾏｸﾛの実行中 */
			kmacexe = 0;
		profset = 0;
	}
}

void memwarn()	/* WM_COMPACTING ﾒｯｾｰｼﾞが来たことを通知 */
{
	BYTE strms[160];

	LoadString(hinst,37,strms,160);
	messageboxO(hfwnd,strms,miwvermes,MB_OK|MB_ICONEXCLAMATION);
}

void editmax(id)	/* 致命的ｴﾗｰの報告（編集限界の報告/ﾒﾓﾘｰ限界/ﾃﾞｨｽｸ空き不足）*/
INT32 id;
{
	if( overflow == 0 ) {	/* 未報告の場合 */
		if( loopon ) {	/* main()関数のﾒｯｾｰｼﾞﾙｰﾌﾟ実行中 */
			if( winhwnd ) {
				if( fatalerr == 10 ) {
					fatalerr = 1;
					goto errend;
				}
			}
		}
		if( id == 1028 )	/* 強制終了ﾒｯｾｰｼﾞ */
			editmax1(id);
		else	  		/* editmax1(id); と同じ処理を後で実行 */
			PostMessage(hfwnd,WM_USER+193,(WPARAM)2,(LPARAM)id);
	}
	errend:
	overflow = 1;		/* 報告済ﾌﾗｸﾞをｾｯﾄ */
	if( kmacexe >= 2 )
		kmacexe = 0;
}

void editmax1(id)	/* 致命的ｴﾗｰの報告（編集限界の報告/ﾒﾓﾘｰ限界/ﾃﾞｨｽｸ空き不足）*/
INT32 id;
{
	BYTE strms[384],strcap[80];

	LoadString(hinst,id,strcap,78);
	LoadString(hinst,id+1,strms,380);
	messageboxO(hfwnd,strms,strcap,MB_OK|MB_ICONSTOP|MB_SYSTEMMODAL);
}

INT32 chkoldf(p)
BYTE *p;
{
	BYTE buff[PATHSIZE+8];

	*(INT32 *)&buff[0] = 45;
	*(INT32 *)&buff[4] = (0x4000|0x0100|0x0000);
	fstrcpy(&buff[8],p);
	return(dialogboxparamO(hinst,IDD_ERRORMES2,hfwnd,HistqueryDlg,(LPARAM)buff));
}

void logodsp(thdc)	/* 起動直後に見本版のﾒｯｾｰｼﾞを表示する */
HDC thdc;
{
	INT32 i,x1,y1,x2,y2,xw,yw,yy;
	RECT rc;
	HBRUSH oldhb;
	DWORD t0;
	BYTE buff[120];

	xw = (sysx1*60);
	yw = (sysy1*8);
	yy = (sysy1/4);
	x1 = ((framex>xw)?((framex-xw)/2):0);
	y1 = ((framey>yw)?((framey-yw)/2):0);
	x2 = x1+xw;
	y2 = y1+yw;
	oldhb = SelectObject(thdc,GetStockObject(WHITE_BRUSH));
	Rectangle(thdc,x1,y1,x2,y2);
	SetTextColor(thdc,0x00000000);
	SetBkColor(thdc,0x00ffffff);
	rc.left = x1+4;
	rc.right = x2-4;
	rc.top = y1+yy+yy;
	rc.bottom = rc.top+sysy1;
	DrawText(thdc,miwvermes,-1,&rc,DT_CENTER|DT_TOP|DT_SINGLELINE);
	getpartstr(689,0,buff,48);
	rc.top += (sysy1+yy+yy);
	rc.bottom = rc.top+sysy1;
	DrawText(thdc,buff,-1,&rc,DT_CENTER|DT_TOP|DT_SINGLELINE);
	rc.top += (sysy1*2);
	rc.bottom = rc.top+sysy1;
	for( i = 0 ; i < 2 ; i++ ) {
		LoadString(hinst,692+i,buff,64);
		DrawText(thdc,buff,-1,&rc,DT_CENTER|DT_TOP|DT_SINGLELINE);
		rc.top += (sysy1+yy);
		rc.bottom = rc.top+sysy1;
	}
	SelectObject(thdc,oldhb);
	for( t0=GetTickCount() ; GetTickCount() < t0+2000 ; ) ; /* 2秒待つ */
}

INT32 keivvv(id)	/* ﾌｧｲﾙ全体に対して、罫線ｺｰﾄﾞの変換を行う */
INT32 id;		/* 0:NEC→JISに変換    1:JIS→NECに変換 */
{
	INT32 pos,numup,size;
	LONG add,add0;
	BYTE *p,*q,c,upflg;
	int v;

	pos = mp->ecurspos;
	add0 = mp->ecursadd;
	waitcurs();
	jmpadd(0,0,0x0000,0);		/* 内部的に先頭へｼﾞｬﾝﾌﾟ */
	mp->edispp = mp->eendp = NULL;
	for( numup = 0 ; ; ) {
		for( p=q=mp->ecurslp,add=mp->ecursladd,upflg=0x00 ; *p != RECMARK ; ) {
			if( ctypex[*p]&CASCII ) {
				*q++ = *p++;
				add++;
			}
			else if( ctypex[*p]&CKANJI1 ) {
				c = *(p+1);
				if( id ) {	/* JIS->NEC */
					if( *p == 0x84 && c >= 0x9f && c <= 0xbe ) {
						*(WORD *)q = keivv1(c);
						q += 2;
						p += 2;
						add += 2;
						upflg = 0x04;	/* 変更ﾏｰｸ */
					}
					else {
						vvvv2:
						*q++ = *p++;
						*q++ = *p++;
						add += 2;
					}
				}
				else {		/* NEC->JIS */
					if( *p != 0x86 )
						goto vvvv2;
					else if( c >= 0x43 && c <= 0x8f ) {
						/* 半角罫線の変換 */
						*q++ = 0x20;
						p += 2;
						add++;
						upflg = 0x04;	/* 変更ﾏｰｸ */
					}
					else if( c >= 0xa2 && c <= 0xed ) {
						/* 全角罫線の変換 */
						*(WORD *)q = keivv2(c);
						q += 2;
						p += 2;
						add += 2;
						upflg = 0x04;	/* 変更ﾏｰｸ */
					}
					else
						goto vvvv2;
				}
			}
			else if( *p == 0x09 ) {
				*q++ = *p++;
				add++;
			}
			else if( ctypex[*p]&CUNIMARK ) {
				if( *p == UCS2MARK ) {
					add += 2;
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
				}
				else {
					add += 4;
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
					*q++ = *p++;
				}
			}
			else if( *p == BINMARK ) {
				*q++ = *p++;
				*q++ = *p++;
				add++;
			}
			else			/* あり得ない */
				p++;
		}
		*q++ = *p++;			/* RECMARK */
		*q++ = c = ((*p++)|upflg);	/* ﾚｺｰﾄﾞ付加情報1ﾊﾞｲﾄ目 */
		*q++ = *p++;			/* ﾚｺｰﾄﾞ付加情報2ﾊﾞｲﾄ目 */
		for( v=3; v < INFOSIZE1; v++)
			*q++ = *p++;		/* ﾚｺｰﾄﾞ付加情報3ﾊﾞｲﾄ目～ */
		if( upflg ) {
			numup++;
			setupdflg(1);
		}
		if( p > q ) {	/* 全角文字(2ﾊﾞｲﾄ文字)→半角文字(1ﾊﾞｲﾄ文字)の変換が1文字以上あった */
			size = (INT32)(mp->ebuffep-p);
			movetxtf(q,p,size);
			mp->ebuffep -= (INT32)(p-q);
		}
		c &= 0x03;
		if( c == LINE3C )
			break;		/* [EOF] */
		mp->ecurslp = q;
		mp->ecursladd = add+(INT32)c;
		mp->ecurslin++;
		if( c )
			mp->ecursnum++;
		pgcheck();
	}
	normcurs();
	mp->ecursp = mp->ecurslp;
	mp->ecursadd = mp->ecursladd;
	mp->ecurscol = mp->ecurscrr = 0;
	mp->ecurspos = mp->winline1-1;
	jmpadd(pos,1,0x0010,add0);
	return(numup);		/* ｺｰﾄﾞ変換した表示行の数を返す */
}

void setyyc()	/* 子ｳｨﾝﾄﾞｳがｽｸﾘｰﾝの下に潜り込んだかどうか */
		/* 子ｳｨﾝﾄﾞｳがﾌﾚｰﾑｳｨﾝﾄﾞｳの下に潜り込んだかどうか、*/
		/* を調査して yycflg のﾋﾞｯﾄ0と1を設定する */
{
	POINT pt;

	pt.x = 0;
	pt.y = mp->yclient;
	ClientToScreen(mp->hwnd,&pt);
	mp->yycflg &= (~0x02);
	if( pt.y >= GetSystemMetrics(SM_CYSCREEN) )
		mp->yycflg |= 0x02;
	pt.x = 0;
	pt.y = framey;
	ClientToScreen(hmdiwnd,&pt);
	ScreenToClient(mp->hwnd,&pt);
	mp->yycflg &= (~0x01);
	if( pt.y < mp->yclient )
		mp->yycflg |= 0x01;
}

/* ﾏｳｽｶｰｿﾙ位置が選択中の範囲内かどうかを調べる 	*/
/* 関数値： 0=編集領域外  1=選択範囲より前  10=選択範囲より後			*/
/*          2=選択範囲中  3=選択範囲中(ｾﾙ内選択)  4=選択範囲中(区切り文字1文字)	*/
INT32 addppp(padd,x,y)
LONG *padd;	/* ﾏｳｽｶｰｿﾙの位置のﾊﾞｲﾄ位置数を返す変数 */
INT32 x;	/* ﾏｳｽｶｰｿﾙのX位置(ｸﾗｲｱﾝﾄ座標) */
INT32 y;	/* ﾏｳｽｶｰｿﾙのY位置(ｸﾗｲｱﾝﾄ座標) */
{
	INT32 i,j,cadd,cladd;
	BYTE *cp,*clp;
	INT32 cblkid;

	if( (i=calposcp(x,y,&cblkid,&cp,&clp,&cadd,&cladd)) == 0 )
		return(0);
	if( cadd < SELADD1 )
		j = 1;
	else if( cadd >= SELADD2 )
		j = 10;
	else {			/* 選択範囲中 */
#ifdef CSVEDIT
		if( i == 1 ) {	/* 指定位置はｾﾙ外文字 ※CSVモードは必ず編集バッファ上(cblkid==-1)  */
			if( mp->csvfile >= 2 && (SELADD1+1) == SELADD2 && ( *cp == mp->csvdelim || *cp == CSVTABSUBST ) )
				j = 4;
			else
				j = 2;
		}
		else {		/* 指定位置はｾﾙ内文字 ※CSVモードなので必ず編集バッファ上(cblkid==-1) */
			if( SELADD1 < cladd )
				j = 2;
			else {
				csvskip(clp,&cladd,NULL);
				if( cladd > SELADD2 )
					j = 3;
				else
					j = 2;
			}
		}
#else
		j = 2;
#endif
	}
	if( padd )
		*padd = cadd;
	return(j);
}

INT32 findegitem(egdata)
struct EGHDATA *egdata;
{
	INT32 i,j;
	BYTE *p0,words[50];

	if( egdata->egmem == NULL )
		return(-1);
	if( egdata->cwords[0] == '\0' )
		return(-1);
	if( egdata->negitem == 0 )
		return(-1);
	p0 = GlobalLock(egdata->egmem);
	for( i = 0 ; i < egdata->negitem ; i++ ) {
		j = fstrcpy(words,p0+egdata->pitem[i]);
		words[j] = words[j+1] = '\0';
		if( aimaicmp(egdata->cwords,words,1) == 0 )
			break;
	}
	if( i < egdata->negitem )
		egdata->iegitem = i;
	else
		i = -1;
	GlobalUnlock(egdata->egmem);
	return(i);
}

INT32 getegstr(w,s)	/* ｶｰｿﾙ行からｲｰｼﾞｰﾍﾙﾌﾟの登録内容を得る */
BYTE *w;	/* 項目名(ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
BYTE *s;	/* 項目の内容(ｼﾌﾄJISﾌｫｰﾏｯﾄ) */
{
	INT32 i,j,k;
	BYTE *p,okflg;

	for( p=mp->ecurslp,i=k=0,okflg=0 ; i < 46 ; ) {
		if( ctypex[*p]&CASCII ) {
			if( *p == 0x20 )
				break;
			*w++ = *p++;
			i++;
		}
		else if( ctypex[*p]&CKANJI1 ) {
			*w++ = *p++;
			*w++ = *p++;
			i += 2;
		}
		else if( *p == 0x09 )
			break;
		else if( ctypex[*p]&CUNIMARK )
			break;
		else if( *p == BINMARK )
			break;
		else if( *p == RECMARK ) {
			k++;
			if( *(p+1)&0x03 )
				break;
			p += INFOSIZE1;
		}
		else		/* あり得ない */
			p++;
	}
	*w = '\0';
	if( i == 0 || *p != 0x20 )
		return(0);	/* 項目名が得られなかった */
	for( ; *p == 0x20 ; p++ ) ;
	for( j = 0 ; j < 4000 ; ) {
		if( ctypex[*p]&CASCII ) {
			*s++ = *p++;
			j++;
		}
		else if( ctypex[*p]&CKANJI1 ) {
			*s++ = *p++;
			*s++ = *p++;
			j += 2;
		}
		else if( *p == 0x09 )
			p++;
		else if( ctypex[*p]&CUNIMARK ) {
			*s++ = (BYTE)NOTJAPANCODE;
			j++;
			if( *p == UCS2MARK )
				p += 3;
			else
				p += 5;
		}
		else if( *p == BINMARK )
			p += 2;
		else if( *p == RECMARK ) {
			k++;
			if( *(p+1)&0x03 ) {
				okflg = 1;
				break;
			}
			p += INFOSIZE1;
			if( p >= mp->ebuffep )
				bpop();
		}
		else		/* あり得ない */
			p++;
	}
	*s = '\0';
	if( okflg ) {
		for( ; k > 0 ; k-- ) {
			if( ccdown(0) )
				break;
			pgcheck();
		}
	}
	return(i+j);
}

INT32 getegdata(hdlg,egdata)	/* ｲｰｼﾞｰﾍﾙﾌﾟ辞書ﾌｧｲﾙを読み出し、そのﾃﾞｰﾀを構造体にｾｯﾄする */
HWND hdlg;
struct EGHDATA *egdata;		/* ｲｰｼﾞｰﾍﾙﾌﾟ辞書構造体へのﾎﾟｲﾝﾀ */
{
	INT32 i,n;
	HANDLE fd;
	DWORD size;
	BYTE *p,*pi,*p0,*pmax;
	BYTE words[50],path[PATHSIZE];

	fstrcpy(&path[fstrcpy(path,cdirec)],easydic);
	if( (fd=createfileM(path,GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING,0)) == INVALID_HANDLE_VALUE ) {
		i = 367;
		egherr:
		egdata->size = 0;
		egdata->negitem = 0;
		egdata->iegitem = -1;
		LoadString(hinst,i,path,200);
		GetWindowText(hdlg,&path[200],64);
		messageboxO(hdlg,path,&path[200],MB_OK|MB_ICONEXCLAMATION);
		return(0);
	}
	size = GetFileSize(fd,NULL);
	if( size == 0xffffffff ) {
		CloseHandle(fd);
		i = 367;
		goto egherr;
	}
	if( egdata->egmem ) {
		GlobalUnlock(egdata->egmem);
		GlobalFree(egdata->egmem);
		egdata->egmem = NULL;
	}
	if( (egdata->egmem=GlobalAlloc(GMEM_MOVEABLE,size+2)) == NULL ) {
		CloseHandle(fd);
		i = 368;
		goto egherr;
	}
	p = p0 = GlobalLock(egdata->egmem);
	if( !ReadFile(fd,p,size,&n,NULL) )
		n = 0;
	CloseHandle(fd);
	*(p+n) = '\n';
	pmax = p+n;
	egdata->size = size+2;
	egdata->negitem = 0;
	egdata->iegitem = -1;
	for( ; p < pmax ; ) {
		pi = p;
		for( i = 0 ; *p > 0x20 && i < 46 ; )
			words[i++] = *p++;
		if( i == 0 || *p != 0x20 )
			goto nextitem;	/* 不当なｷｰﾜｰﾄﾞ */
		words[i] = '\0';
		words[i+1] = '\0';
		for( *p++ = '\0' ; *p == 0x20 ; p++ ) ;
		egdata->pitem[egdata->negitem] = (DWORD)(pi-p0);
		egdata->pcont[egdata->negitem] = (DWORD)(p-p0);
		if( egdata->iegitem == -1 && egdata->cwords[0] ) {
			if( aimaicmp(egdata->cwords,words,0) == 0 )
				egdata->iegitem = egdata->negitem;
		}
		egdata->negitem++;
		nextitem:
		for( ; *p != 0x0a ; p++ ) ;	/* 項目の区切り 0x0a を探す */
		p++;
	}
	GlobalUnlock(egdata->egmem);
	return(egdata->negitem);
}

INT32 getegcont(buff,p)		/* ｲｰｼﾞｰﾍﾙﾌﾟ項目内容を変形内部ﾌｫｰﾏｯﾄに変換する */
BYTE *buff;	/* 変形内部ﾌｫｰﾏｯﾄ */
BYTE *p;	/* ｲｰｼﾞｰﾍﾙﾌﾟ項目内容(最後がｺｰﾄﾞ0x0a) */
{
	BYTE *q0,*q,*qmax;

	for( q0=q=buff,qmax=buff+4032 ; q < qmax && *p != 0x0a ; ) {
		if( *p == '\\' ) {
			p++;
			if( *p == 'n' ) {
				*q++ = 0x0d;
				*q++ = 0x0a;
				p++;
				continue;
			}
			else if( *p == 't' ) {
				*q++ = 0x09;
				p++;
				continue;
			}
		}
		if( ctypesjis[*p]&CASCII ) {
			*q++ = *p++;
		}
		else if( ctypesjis[*p]&CKANJI1 ) {
			*q++ = *p++;
			*q++ = *p++;
		}
		else {		/* 0x0d、制御ｺｰﾄﾞなど */
			p++;
		}
	}
	*q = '\0';
	return((INT32)(q-q0));
}

void rebuildmenufont() /* メニューのフォントを再構築  */
{
	LOGFONT lffix;
	NONCLIENTMETRICS m = {sizeof(NONCLIENTMETRICS)};
	SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(m), &m, 0);

	if (hmenuf) {
		DeleteObject(hmenuf);
	}
	if (hmenufixf) {
		DeleteObject(hmenufixf);
	}

	/* メニュー用フォント */
	hmenuf = CreateFontIndirect(&m.lfMenuFont);

	/* ファイル名用の等幅フォント */
	lffix.lfHeight = m.lfMenuFont.lfHeight;
	lffix.lfWidth = 0;
	lffix.lfEscapement = 0;
	lffix.lfOrientation = 0;
	lffix.lfWeight =  m.lfMenuFont.lfWeight;
	lffix.lfItalic =  m.lfMenuFont.lfItalic;
	lffix.lfUnderline =  m.lfMenuFont.lfUnderline;
	lffix.lfStrikeOut =  m.lfMenuFont.lfStrikeOut;
	lffix.lfCharSet = SHIFTJIS_CHARSET;
	lffix.lfOutPrecision = OUT_DEFAULT_PRECIS;
	lffix.lfClipPrecision = CLIP_CHARACTER_PRECIS;
	lffix.lfQuality = DEFAULT_QUALITY;
	lffix.lfPitchAndFamily = FF_DONTCARE|FIXED_PITCH;
	strcpy(lffix.lfFaceName, fntnam3);

	hmenufixf = CreateFontIndirect(&lffix);
}

/* 起動モードを返却 */
STARTUPMODE getstartupmode(void)
{
	if( sssmode&SYS_UNIQ )
	{
		if( sssmode&SYS_SDILIST )
			return SM_LIST;	/* SDI 独立リストウィンドウモード */
		else
			return SM_SDI;	/* SDI 非独立リストウィンドウモード */
	}
	else
	{
		return SM_MDI;	/* MDIモード */
	}
}

/* 2個の要素の入れ替え */
void swap(void *a, void *b, INT32 size)
{
	BYTE *pa = a;
	BYTE *pb = b;
	BYTE t;
	INT32 i;
	for( i = 0; i < size; i ++ ) {
		t = pa[i];
		pa[i] = pb[i];
		pb[i] = t;
	}
}

/* 配列の要素を反転 */
void reverse_array(
	void *a,	/* 配列 */
	INT32 c,	/* 配列の要素数 */
	INT32 size)	/* 配列の要素サイズ */
{
	BYTE *l = (BYTE *)a;
	BYTE *r = (BYTE *)a + ((c-1) * size);

	for( ; l < r; l += size, r -= size )
		swap(l, r, size);
}

/* 配列要素をshift個回転 */
void rotate_array(
	void  *a,	/* 配列 */
	INT32 c,	/* 配列の要素数 */
	INT32 size,	/* 配列要素のサイズ */
	INT32 shift)	/* 回転数(+で右 -で左 */
{
	if( 0 <= shift )	rrotate_array(a, c, size, shift);
	else			lrotate_array(a, c, size, -shift);
}

/* 配列要素を右へshift個回転 */
void rrotate_array(
	void  *a,	/* 配列 */
	INT32 c,	/* 配列の要素数 */
	INT32 size,	/* 配列要素のサイズ */
	INT32 shift)	/* 回転数 */
{
						/* abcdefgを右へ3回転 要素を左右に分離 abcd|efg  */
	reverse_array(a,                        c,         size);	/* abcd|efg => gfe|dcba */
	reverse_array(a,                        shift,     size);	/* gfe|dcba => efg|dcba */
	reverse_array((BYTE *)a + size * shift, c - shift, size);	/* efg|dcba => efg|abcd */
}

/* 配列要素を左へshift個回転 */
void lrotate_array(
	void  *a,	/* 配列 */
	INT32 c,	/* 配列の要素数 */
	INT32 size,	/* 配列要素のサイズ */
	INT32 shift)	/* 回転数 */
{
						/* abcdefgを左へ3回転 要素を左右に分離 abc|defg  */
	reverse_array(a,                        shift,     size);	/* abc|defg => cba|defg */
	reverse_array((BYTE *)a + size * shift, c - shift, size);	/* cba|defg => cba|gfed */
	reverse_array(a,                        c,         size);	/* cba|gfed => defg|abc */
}

/* 2個のMIWMENUDATAの入れ替え */
void swapMIWMENUDATA(struct MIWMENUDATA *a, struct MIWMENUDATA *b)
{
	swap(a, b, sizeof(struct MIWMENUDATA));
}

/* POINT構造体構築 */
POINT MakePoint(x,y)
LONG x,y;	/* x,y座標 */
{
	POINT pt = {x,y};
	return pt;
}

/* RECT構造体幅計算 */
LONG RectWidth(rect)
RECT rect;
{
	return rect.right-rect.left;
}

/* RECT構造体高さ計算 */
LONG RectHeight(rect)
RECT rect;
{
	return rect.bottom-rect.top;
}

/* RECT構造体構築 */
RECT MakeRect(x0,y0,x1,y1)
LONG x0,y0,x1,y1;
{
	RECT r = {x0,y0,x1,y1};
	return r;
}

RECT MakeRectWH(x,y,w,h)
LONG x,y,w,h;
{
	RECT r = {x,y,x+w,y+h};
	return r;
}

/* RECT2からRECT構築 */
RECT Rect2ToRect(const RECT2 *r2)
{
	RECT r = {r2->x, r2->y, r2->x + r2->w, r2->y + r2->h};
	return r;
}

/* RECTからRECT2構築 */
RECT2 RectToRect2(const RECT *r)
{
	RECT2 r2 = {r->left, r->top, r->right - r->left, r->bottom - r->top};
	return r2;
}

/* RECTのスクリーン座標→クライアント座標変換 */
void ScreenToClientRect(hwnd,prect)
HWND hwnd;
RECT* prect;
{
	ScreenToClient(hwnd, (POINT*)&prect->left);
	ScreenToClient(hwnd, (POINT*)&prect->right);
}

/* RECTのクライアント座標→スクリーン座標変換 */
void ClientToScreenRect(hwnd,prect)
HWND hwnd;
RECT* prect;
{
	ClientToScreen(hwnd, (POINT*)&prect->left);
	ClientToScreen(hwnd, (POINT*)&prect->right);
}

/* RECT指定によるMoveWindow */
BOOL MoveWindowByRect(hwnd,prect,bRepaint)
HWND hwnd;
RECT *prect;
BOOL bRepaint;
{
	return MoveWindow(hwnd,prect->left,prect->top,
		prect->right-prect->left,prect->bottom-prect->top,bRepaint);
}

/* ウインドウ矩形取得(Vista以降のDWM補正付 */
BOOL GetWindowRectWithDWM(hwnd,pRect)
HWND  hwnd;
RECT* pRect;
{
	if( dwmlib.pfnDwmGetWindowAttribute
		&& SUCCEEDED(dwmlib.pfnDwmGetWindowAttribute(
			hwnd, DWMWA_EXTENDED_FRAME_BOUNDS,pRect,sizeof(*pRect))) ) {
		return TRUE;
	}
	else {
		return GetWindowRect(hwnd,pRect);
	}
}

/* RECT指定によるMoveWindow(Vista以降のDWM補正付) */
BOOL MoveWindowByRectWithDWM(hwnd,prect,bRepaint)
HWND hwnd;
RECT *prect;
BOOL bRepaint;
{
	RECT rectDWM    = *prect;
	RECT rectNormal = *prect;
	RECT rect       = *prect;

	GetWindowRectWithDWM(hwnd,&rectDWM);
	GetWindowRect(hwnd,&rectNormal);

	rect.left   += rectNormal.left - rectDWM.left;
	rect.top    += rectNormal.top  - rectDWM.top;
	rect.right  -= rectDWM.right   - rectNormal.right;
	rect.bottom -= rectDWM.bottom  - rectNormal.bottom;

	return MoveWindow(hwnd,rect.left,rect.top,
		rect.right-rect.left,rect.bottom-rect.top,bRepaint);
}

/* クライアントサイズ指定でのウインドウリサイズ(ウインドウ位置は変化なし) */
BOOL ResizeWindowByClientSize(HWND hwnd, LONG w, LONG h, BOOL bRepaint)
{
	HWND hwndParent = GetParent(hwnd);
	RECT rectWindow;
	RECT rectClient;

	GetWindowRect(hwnd, &rectWindow);
	GetClientRect(hwnd, &rectClient);

	//新しいウインドウサイズ=非クライアントサイズ+新クライアントサイズ
	w = RectWidth(rectWindow) - RectWidth(rectClient) + w;
	h = RectHeight(rectWindow) - RectHeight(rectClient) + h;

	rectWindow.right = rectWindow.left + w;
	rectWindow.bottom = rectWindow.top + h;

	if( hwndParent ) {
		ScreenToClientRect(hwndParent, &rectWindow);
	}

	return MoveWindowByRect(hwnd, &rectWindow, bRepaint);
}

/* TrackPopupMenu APIをタブレット設定に従いメニュー表示位置を調整する */
BOOL MIWTrackPopupMenu(
	HMENU hMenu,
	UINT uFlags,
	int x,
	int y,
	int nReserved,
	HWND hWnd,
	CONST RECT *prcRect,
	int refwidth)	/* メニュー表示位置x,yにおいて、基準とした要素の幅 */
{
	/* ポップアップメニューが右寄せ(=Table設定で右利き)ならば、*/
	/* 左上揃えのメニューを右上揃えに変換                      */
	/* ※非Tablet環境では、左揃えが返却される */
	UINT HFLAG = TPM_LEFTALIGN|TPM_CENTERALIGN|TPM_RIGHTALIGN;
	UINT VFLAG = TPM_TOPALIGN|TPM_VCENTERALIGN|TPM_BOTTOMALIGN;

	BOOL fRightAligned = TRUE;
	if( SystemParametersInfo(SPI_GETMENUDROPALIGNMENT, 0, &fRightAligned, 0)
	 && fRightAligned ) {
		if( (uFlags & HFLAG) == TPM_LEFTALIGN
		 && (uFlags & VFLAG) == TPM_TOPALIGN ) {
			 uFlags &= ~HFLAG;
			 uFlags |= TPM_RIGHTALIGN;

			 x += refwidth;
		}
	}

	return TrackPopupMenu(hMenu, uFlags, x, y, nReserved, hWnd, prcRect);
}

/* 指定の矩形を指定の色で塗りつぶす */
void FillSolidRect(HDC hdc, COLORREF cr, const RECT* rc)
{
	COLORREF old = SetBkColor(hdc, cr);
	ExtTextOut(hdc, 0, 0, ETO_OPAQUE, rc, NULL, 0, NULL);
	SetBkColor(hdc, old);
}

/* themelibのEnableThemeDialogTexture呼び出し */
HRESULT MIWEnableThemeDialogTexture(HWND hwnd, DWORD dwFlags)
{
	return themelib.bIsThemeActive
		? themelib.pfnEnableThemeDialogTexture(hwnd, dwFlags)
		: 0;
}

/* エディットボックスに透かし文字を設定 */
void seteditcuebanner(
	HWND hwnd,	/* エディットボックスウィンドウハンドル */
	BOOL focus,	/* フォーカス時も透かし文字を表示するか？ */
	BYTE *text)	/* 透かし文字 */
{
	//※UNICODEメッセージを使わないと文字化けする
	WCHAR wbuf[256];
	exsjistounicode(text, wbuf);
	SendMessageW(hwnd, EM_SETCUEBANNER, focus, (LPARAM)wbuf);
}

/* エディットボックスに透かし文字を設定(リソース文字列) */
void seteditcuebannerrc(
	HWND hwnd,	/* エディットボックスウィンドウハンドル */
	BOOL focus,	/* フォーカス時も透かし文字を表示するか？ */
	INT32 id,	/* 文字列リソースID */
	INT32 seq)	/* 文字列リソース位置(-1はgetpartstrを使わない) */
{
	BYTE buf[256];

	if( seq == -1 )
	{
		LoadString(hinst, id, buf, countof(buf));
	}
	else
	{
		getpartstr(id, seq, buf, countof(buf));
	}

	seteditcuebanner(hwnd, focus, buf);
}


/* 内部フォーマット1文字の種別 */
DWORD miwchartype(const BYTE* p)
{
	if( ctypex[*p]&CASCII )		return MIWCHAR_ASCII;	/* 0x20～0x7f:ASCII/0xa0～0xdf:半角カナ */
	else if( ctypex[*p]&CKANJI1 )	return MIWCHAR_KANJI;	/* SJIS漢字 */
	else if( *p == TABMARK )	return MIWCHAR_TAB;	/* TAB */
	else if( *p == RECMARK )	return MIWCHAR_REC;	/* 0xff:表示行付加バイト */
	else if( ctypex[*p]&CUNIMARK )	return MIWCHAR_UNICODE;	/* 非日本語UNICODE文字 */
	else if( *p == BINMARK )	return MIWCHAR_BIN;	/* 0x0b:バイナリ */
	else if( *p == EXTMARK )	return MIWCHAR_EXT;	/* 0xfe:拡張 */
	else				return MIWCHAR_INVALID;	/* 異常 */
}

/* 内部フォーマット1文字のバイト数 */
INT32 miwcharplen(const BYTE* p)
{
	if( ctypex[*p]&CASCII )		return 1;		/* 0x20～0x7f:ASCII/0xa0～0xdf:半角カナ */
	else if( ctypex[*p]&CKANJI1 )	return 2;		/* SJIS漢字 */
	else if( *p == TABMARK )	return 1;		/* TAB */
	else if( *p == RECMARK )	return INFOSIZE1;	/* 0xff:表示行付加バイト */
	else if( ctypex[*p]&CUNIMARK ) {			/* 非日本語UNICODE文字 */
		if( *p == UCS2MARK )	return 3;		/* 0x0e:USC2 */
		else			return 5;		/* 0x0f～0x1e:USC4 */
	}
	else if( *p == BINMARK )	return 2;		/* 0x0b:バイナリ */
	else if( *p == EXTMARK ) {				/* 0xfe:拡張 */
		if( *(p+1) == TABMARK )				return 2;	/* 擬似タブ */
		else if ( *(p+1) == 0x0d ||  *(p+1) == 0x0d )	return 2;	/* 擬似改行 */
		else						return 2;	/* 異常 */
	}
	else				return 1;		/* 異常 */
}

/* 内部フォーマット1文字の表示桁数 */
INT32 miwcharwlen(
	const BYTE* p,
	const INT32* w)	/* 表示桁数算出用の現在値(NULL指定可) */
{
	if( ctypex[*p]&CASCII )		return 1;			/* 0x20～0x7f:ASCII/0xa0～0xdf:半角カナ */
	else if( ctypex[*p]&CKANJI1 )	return 2;			/* SJIS漢字 */
	else if( *p == TABMARK )	return w ? gethtabwid(*w) : 1;	/* TAB */
	else if( *p == RECMARK )	return 0;			/* 0xff:表示行付加バイト */
	else if( ctypex[*p]&CUNIMARK )	return 2;			/* 非日本語UNICODE文字 */
	else if( *p == BINMARK )	return 1;			/* 0x0b:バイナリ */
	else if( *p == EXTMARK ) {					/* 0xfe:拡張 */
		if( *(p+1) == TABMARK )				return w ? gethtabwid(*w) : 1;	/* 擬似タブ */
		else if ( *(p+1) == 0x0d ||  *(p+1) == 0x0d )	return 0;			/* 擬似改行 */
		else						return 0;			/* 異常 */
	}
	else				return 0;			/* 異常 */
}

/* 内部フォーマット1文字のバイト位置数 */
INT32 miwcharalen(const BYTE* p)
{
	if( ctypex[*p]&CASCII )		return 1;		/* 0x20～0x7f:ASCII/0xa0～0xdf:半角カナ */
	else if( ctypex[*p]&CKANJI1 )	return 2;		/* SJIS漢字 */
	else if( *p == TABMARK )	return 1;		/* TAB */
	else if( *p == RECMARK )	return *(p+1)&0x3;	/* 0xff:表示行付加バイト */
	else if( ctypex[*p]&CUNIMARK ) {			/* 非日本語UNICODE文字 */
		if( *p == UCS2MARK )	return 2;		/* 0x0e:USC2 */
		else			return 4;		/* 0x0f～0x1e:USC4 */
	}
	else if( *p == BINMARK )	return 1;		/* 0x0b:バイナリ */
	else if( *p == EXTMARK ) {				/* 0xfe:拡張 */
		if( *(p+1) == TABMARK )				return 1;	/* 擬似タブ */
		else if ( *(p+1) == 0x0d ||  *(p+1) == 0x0d )	return 1;	/* 擬似改行 */
		else						return 0;	/* 異常 */
	}
	else				return 1;		/* 異常 */
}

/* 内部フォーマット拡張文字種別を返却 */
DWORD miwextchartype(
	const BYTE* p,	/* 内部フォーマットバッファ */
	const BYTE* e)	/* 内部フォーマットバッファ終端(NULL指定可能 その場合CRLF判定が行われない) */
{
	if( *p++ != EXTMARK )
		return MIWEXTCHAR_INVALID;

	if( *p == TABMARK )	return MIWEXTCHAR_PSTAB;	/* 擬似タブ */
	else if ( *p == 0x0a )	return MIWEXTCHAR_PSLF;		/* 擬似LF   */
	else if ( *p == 0x0d ) {
		if( e && p+2 < e && *(p+1) == EXTMARK && *(p+2) == 0x0a )
			return MIWEXTCHAR_PSCRLF;		/* 擬似CRLF */
		else
			return MIWEXTCHAR_PSCR;			/* 擬似CR */
	}
	else {
		return MIWEXTCHAR_INVALID;			/* 異常 */
	}
}

/* 内部フォーマット拡張コードのバイト長取得 */
INT32 miwextcharplen(
	const BYTE* p,	/* 内部フォーマットバッファ */
	const BYTE* e)	/* 内部フォーマットバッファ終端(NULL指定可能 その場合CRLF判定が行われない) */
{
	switch (miwextchartype(p, e))
	{
	case MIWEXTCHAR_PSTAB:	return 2;
	case MIWEXTCHAR_PSCR:	return 2;
	case MIWEXTCHAR_PSLF:	return 2;
	case MIWEXTCHAR_PSCRLF:	return 4;
	default:		return 2;
	}
}

/* 内部フォーマット拡張コードの表示桁数取得 */
INT32 miwextcharwlen(const BYTE* p, const BYTE* e, const INT32* w)
{
	switch (miwextchartype(p, e))
	{
	case MIWEXTCHAR_PSTAB:	return w ? gethtabwid(*w) : 1;
	case MIWEXTCHAR_PSCR:	return 0;
	case MIWEXTCHAR_PSLF:	return 0;
	case MIWEXTCHAR_PSCRLF:	return 0;
	default:		return 0;
	}
}

/* 内部フォーマット拡張コードのバイト位置数取得 */
INT32 miwextcharalen(const BYTE* p, const BYTE* e)
{
	switch (miwextchartype(p, e))
	{
	case MIWEXTCHAR_PSTAB:	return 1;
	case MIWEXTCHAR_PSCR:	return 1;
	case MIWEXTCHAR_PSLF:	return 1;
	case MIWEXTCHAR_PSCRLF:	return 2;
	default:		return 0;
	}
}

/* 内部フォーマットループにおいてEXTMARKでのポインタ、表示桁、バイト位置数を更新 */
INT32 miwextcharskip(const BYTE** p, INT32* w, LONG* a)
{
	if( **p == EXTMARK ) {
		if( w ) *w += miwextcharwlen(*p, NULL, w);
		if( a ) *a += miwextcharalen(*p, NULL);
		*p += miwextcharplen(*p, NULL);
		return 1;
	}
	else {
		return 0;	/* 拡張コードではない */
	}
}

/* BYTE*⇔char* 相互変換 */
BYTE* tobp(char* p)
{
	return (BYTE*)p;
}

char* tocp(BYTE* p)
{
	return (char*)p;
}

const BYTE* tocbp(const char* p)
{
	return (const BYTE*)p;
}

const char* toccp(const BYTE* p)
{
	return (const char*)p;
}

/* 配列用メモリ構造体 */
typedef struct tagINTERNAL_ARRAY_INFO
{
	BYTE  signature[8];	/* 正当性判定用のシグネチャ */
	INT32 elementsize;	/* 配列要素サイズ */
	INT32 count;		/* 配列要素数 */
	INT32 alloccount;	/* 確保済み配列要素数 */
	BYTE  buf[0];		/* 配列用バッファ */
} INTERNAL_ARRAY_INFO;

static BYTE ARRAY_INFO_SIGNATURE[8] = "@AryInf+";

/* 配列用メモリ確保 */
void* arrayalloc(INT32 elementsize, INT32 count)
{
	/* INTERNAL_ARRAY_INFO を先頭に追加したメモリバッファを確保 */
	void* p = GlobalAlloc(GPTR, sizeof(INTERNAL_ARRAY_INFO) + elementsize * count);
	if (p)
	{
		INTERNAL_ARRAY_INFO* piai = (INTERNAL_ARRAY_INFO*)p;
		memcpy(piai->signature, ARRAY_INFO_SIGNATURE, sizeof(piai->signature));
		piai->elementsize = elementsize;
		piai->count       = count;
		piai->alloccount  = count;

		/* INTERNAL_ARRAY_INFOを除いたバッファを返却 */
		return piai + 1;
	}
	else
	{
		return NULL;
	}
}

/* 配列用メモリ開放 */
void arrayfree(void* p)
{
	if (p)
	{
		INTERNAL_ARRAY_INFO* piai = ((INTERNAL_ARRAY_INFO*)p) - 1;
		if (memcmp(piai->signature, ARRAY_INFO_SIGNATURE, sizeof(piai->signature)) == 0)
		{
			GlobalFree(piai);
		}
		else
		{
			assert(!"invalid array memory");
		}
	}
}

/* 配列用メモリリサイズ */
BOOL arrayrealloc(void** pp, INT32 newcount)
{
	if (pp && *pp)
	{
		void* p = *pp;

		INTERNAL_ARRAY_INFO* piai = ((INTERNAL_ARRAY_INFO*)p) - 1;
		if (memcmp(piai->signature, ARRAY_INFO_SIGNATURE, sizeof(piai->signature)) == 0)
		{
			/* 指定サイズ確保していれば再確保不要 */
			if (newcount <= piai->alloccount)
			{
				piai->count = newcount;
				return TRUE;
			}
			/* 再確保 */
			else
			{
				void* np = arrayalloc(piai->elementsize, newcount);
				if (np == NULL)
					return FALSE;	/* 確保失敗 */

				/* 確保成功、バッファ入れ替え */
				memcpy(np, piai->buf, piai->elementsize * piai->count);
				*pp = np;

				GlobalFree(piai);
				return TRUE;
			}
		}
		else
		{
			assert(!"invalid array memory");
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}
}

/* 配列用メモリから要素数を取得 */
INT32 arraycount(void* p)
{
	if (p)
	{
		INTERNAL_ARRAY_INFO* piai = ((INTERNAL_ARRAY_INFO*)p) - 1;
		if (memcmp(piai->signature, ARRAY_INFO_SIGNATURE, sizeof(piai->signature)) == 0)
		{
			return piai->count;
		}
		else
		{
			assert(!"invalid array memory");
			return 0;
		}
	}
	else
	{
		return 0;
	}
}

/* 指定位置のビットを立てた32ビット値返却 */
DWORD bit(int bitno)
{
	return 1 << bitno;
}

/* 指定の32bit値から最初にたっているビット番号を求める(0ビットから検索) */
extern INT32 bitno(DWORD b)
{
	int i;
	for (i = 0; i < 32; i++)
	{
		if (b & (1 << i))
			return i;
	}

	return -1;
}

/* 指定位置のビット状態取得 */
BOOL getbit(DWORD dw, int bitno)
{
	return dw & bit(bitno);
}

/* 指定位置のビット状態変更 */
void setbit(DWORD* pdw, int bitno, BOOL set)
{
	DWORD b = bit(bitno);

	if (set)
		*pdw |= b;	//セット
	else
		*pdw &= ~b;	//クリア

}

/* 指定のフラグ状態変更 */
void setflag(DWORD* pdw, DWORD flag, BOOL set)
{
	if (set)
		*pdw |= flag;	//セット
	else
		*pdw &= ~flag;	//クリア
}

/* 2つのバッファが交差するか？ */
BOOL crossesbuffer(LONG sa, LONG ea, LONG sb, LONG eb)
{
	/* x0-x1 y0-y1の交差条件 x0<y1 && y0<x1 */
	return sa < eb && sb < ea;
}

/* キーワード定義バッファコメント情報フィールドを返却 */
BYTE* kw_ccc(EB_KEYWD* p)
{
	return p->end_cmt;	//行末コメントから
}

/* キーワード定義バッファ先頭アドレスを返却 */
BYTE* kw_ppp0(EB_KEYWD* p)
{
	return (BYTE*)p;
}

/* キーワード定義バッファ終端アドレスを返却 */
BYTE* kw_pppx(EB_KEYWD* p)
{
	return (BYTE*)(p + 1);
}

/* EDITBUF構造体取得 */
struct EDITBUF *etext_editbuf(struct ETEXT *mp)
{
	return (struct EDITBUF *)mp->base;
}

/* テキストモード判定 */
BOOL istextmode(const struct ETEXT *mp)
{
	return mp->bin2mode == 0 && mp->csvfile == 0;
}

/* CSVモード判定 */
BOOL iscsvmode(const struct ETEXT *mp)
{
	return 2 <= mp->csvfile;
}

/* バイナリモード判定 */
BOOL isbinmode(const struct ETEXT *mp)
{
	return mp->bin2mode != 0;
}
