
#define UNICODE
#define _UNICODE

#define USE_TCL_STUBS

#include <tcl.h>
#include <windows.h>


#if defined(_MSC_VER) && defined(USE_TCL_STUBS)
	// mark this .obj as needing tcl's Stubs library
#   pragma comment(lib,STRINGIFY(JOIN(tclstub,JOIN(TCL_MAJOR_VERSION,JOIN(TCL_MINOR_VERSION,.lib)))))
#   if !defined(_MT) || !defined(_DLL) || defined(_DEBUG)
	// the requirement for msvcrt.lib from tclstubXX.lib should
        // be removed.
#       pragma comment(linker, "-nodefaultlib:msvcrt.lib")
#   endif
#endif

#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLEXPORT




/* blocks */

int BlocksNewCmd(ClientData clientdata, Tcl_Interp *interp,
		 int argc, char *argv[]);
int BlocksGetCmd(ClientData clientdata, Tcl_Interp *interp,
		 int argc, char *argv[]);
int BlocksDelCmd(ClientData clientdata, Tcl_Interp *interp,
		 int argc, char *argv[]);


static Tcl_HashTable blocks_hash;

typedef struct {
	char *dir;
	int first_time;
	HANDLE h;
	WIN32_FIND_DATA data;
} blocks_finder;

static int blocks_handle_count = 0;







// ==title== dexfend begin


static int dexfex_ready_for_next = 0;
static HANDLE dexfex_xh = INVALID_HANDLE_VALUE;
static WIN32_FIND_DATA dexfex_xfd;



int DexfexNewObjCmd(ClientData clientData, Tcl_Interp *interp,
		    int objc, Tcl_Obj *CONST objv[]);

int DexfexNextObjCmd(ClientData clientData, Tcl_Interp *interp,
		    int objc, Tcl_Obj *CONST objv[]);







EXTERN int
Blocks_Init(Tcl_Interp *interp)
{
	if (Tcl_InitStubs(interp, "8.1", 0) == NULL) {
		return TCL_ERROR;
	}
	
	Tcl_InitHashTable(&blocks_hash, TCL_STRING_KEYS);

	Tcl_CreateCommand(interp, "blocks_new", (Tcl_CmdProc *)BlocksNewCmd,
		(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	
	Tcl_CreateCommand(interp, "blocks_get", (Tcl_CmdProc *)BlocksGetCmd,
		(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
	
	Tcl_CreateCommand(interp, "blocks_del", (Tcl_CmdProc *)BlocksDelCmd,
		(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);

	// let the tcl file do this bit
	//Tcl_PkgProvide(interp, "blocks", "1.0");



	Tcl_CreateObjCommand(interp, "dexfex_new", DexfexNewObjCmd,
		(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);

	Tcl_CreateObjCommand(interp, "dexfex_next", DexfexNextObjCmd,
		(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);


	return TCL_OK;
}






Tcl_Obj* new_string_obj_for_twin_dwords(DWORD hi, DWORD lo) {

	LARGE_INTEGER xxsize;
	char size_buffer[66];

	// use the entire 64bit
	xxsize.LowPart  = lo;
	xxsize.HighPart = hi;
	_i64toa(xxsize.QuadPart, size_buffer, 10);  // base 10

	return(Tcl_NewStringObj(size_buffer, -1));
}

Tcl_Obj* new_string_obj_from_dwfattr(DWORD dwfattr) {

	Tcl_Obj *obj;
	Tcl_DString ds;

	Tcl_DStringInit(&ds);

	if (dwfattr & FILE_ATTRIBUTE_READONLY) {
		Tcl_DStringAppend(&ds, "r", -1);
	}
	if (dwfattr & FILE_ATTRIBUTE_HIDDEN) {
		Tcl_DStringAppend(&ds, "h", -1);
	}
	if (dwfattr & FILE_ATTRIBUTE_SYSTEM) {
		Tcl_DStringAppend(&ds, "s", -1);
	}
	if (dwfattr & FILE_ATTRIBUTE_ARCHIVE) {
		Tcl_DStringAppend(&ds, "a", -1);
	}

	obj = Tcl_NewStringObj(Tcl_DStringValue(&ds), -1);
	Tcl_DStringFree(&ds);

	return obj;

}

Tcl_Obj* new_string_obj_from_ft(FILETIME *ft) {

	LARGE_INTEGER timex;
	char time_t_buffer[20];

	// timex can be used as a 64bit int (timex.QuadPart)
	timex.HighPart = ft->dwHighDateTime;
	timex.LowPart  = ft->dwLowDateTime;

	// had to add 'LLU' so mingw would compile without a warning (unsigned long long)
	timex.QuadPart = (timex.QuadPart - 116444736000000000LLU) / 10000000;

	// timex.LowPart now contains time_t

	_itoa(timex.LowPart, time_t_buffer, 10);

	return(Tcl_NewStringObj(time_t_buffer, -1));
}



char* wchar_to_utf(wchar_t *src, Tcl_DString *dsPtr) {
	return Tcl_WinTCharToUtf((TCHAR *)src, -1, dsPtr);
}

wchar_t* utf_to_wchar(char* src, Tcl_DString *dsPtr) {
	return (wchar_t *)Tcl_WinUtfToTChar(src, -1, dsPtr);
}

Tcl_Obj* new_string_obj_from_winstring(wchar_t *src) {

	Tcl_Obj *obj;
	Tcl_DString ds;
	char *utf;

	Tcl_DStringInit(&ds);
	utf = wchar_to_utf(src, &ds);
	obj = Tcl_NewStringObj(utf, -1);
	Tcl_DStringFree(&ds);

	return obj;
}


Tcl_Obj* read_win32_find_data(Tcl_Interp *interp, WIN32_FIND_DATA *xfd) {

	Tcl_Obj *z;
	Tcl_Obj *obj_type, *obj_fn, *obj_alt, *obj_mtime, *obj_ctime, *obj_atime, *obj_attr;
	Tcl_Obj *obj_size;


	z = Tcl_NewListObj(0, NULL);


	if (xfd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		obj_type = Tcl_NewStringObj("d", -1);
		obj_size = Tcl_NewStringObj("", -1);
	} else {
		obj_type = Tcl_NewStringObj("f", -1);
		obj_size = new_string_obj_for_twin_dwords(xfd->nFileSizeHigh, xfd->nFileSizeLow);
	}


	obj_fn  = new_string_obj_from_winstring(xfd->cFileName);
	obj_alt = new_string_obj_from_winstring(xfd->cAlternateFileName);

	obj_mtime = new_string_obj_from_ft(&xfd->ftLastWriteTime);
	obj_ctime = new_string_obj_from_ft(&xfd->ftCreationTime);
	obj_atime = new_string_obj_from_ft(&xfd->ftLastAccessTime);

	obj_attr = new_string_obj_from_dwfattr(xfd->dwFileAttributes);	

	Tcl_ListObjAppendElement(interp, z, obj_type);
	Tcl_ListObjAppendElement(interp, z, obj_fn);
	Tcl_ListObjAppendElement(interp, z, obj_alt);
	Tcl_ListObjAppendElement(interp, z, obj_size);
	Tcl_ListObjAppendElement(interp, z, obj_mtime);
	Tcl_ListObjAppendElement(interp, z, obj_ctime);
	Tcl_ListObjAppendElement(interp, z, obj_atime);
	Tcl_ListObjAppendElement(interp, z, obj_attr);
	return z;
}



int DexfexNewObjCmd(ClientData clientData, Tcl_Interp *interp,
		    int objc, Tcl_Obj *CONST objv[])
{

	Tcl_Obj *resultPtr, *resultList;
	char *path_utf;
	Tcl_DString path_ds;
	wchar_t *path_wchar;


	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "path");
		return TCL_ERROR;
	}

	path_utf = Tcl_GetString(objv[1]);



	if (dexfex_ready_for_next && dexfex_xh != INVALID_HANDLE_VALUE) {
		FindClose(dexfex_xh);
	}
	dexfex_ready_for_next = 0;
	dexfex_xh = INVALID_HANDLE_VALUE;



	Tcl_DStringInit(&path_ds);
	path_wchar = utf_to_wchar(path_utf, &path_ds);

	dexfex_xh = FindFirstFile(path_wchar, &dexfex_xfd);

	Tcl_DStringFree(&path_ds);



	if (dexfex_xh == INVALID_HANDLE_VALUE) {

		// difference between not being able to read a dir, and the dir being empty

		if (GetLastError() == ERROR_FILE_NOT_FOUND) {
			resultPtr = Tcl_GetObjResult(interp);
			Tcl_SetStringObj(resultPtr, "", -1);
			return TCL_OK;
		} else {
			resultPtr = Tcl_GetObjResult(interp);
			Tcl_SetStringObj(resultPtr, "could not open dir for reading", -1);
			return TCL_ERROR;
		}
	}

	dexfex_ready_for_next = 1;

	resultList = read_win32_find_data(interp, &dexfex_xfd);
	Tcl_SetObjResult(interp, resultList);
	return TCL_OK;
}


int DexfexNextObjCmd(ClientData clientData, Tcl_Interp *interp,
		    int objc, Tcl_Obj *CONST objv[])
{


// decide where to put in the closes


	if (!dexfex_ready_for_next) {
		Tcl_Obj *result = Tcl_NewStringObj("not ready for next", -1);
		Tcl_SetObjResult(interp, result);
		return TCL_ERROR;
	}

	if (!FindNextFile(dexfex_xh, &dexfex_xfd)) {
		FindClose(dexfex_xh);
		dexfex_ready_for_next = 0;
		dexfex_xh = INVALID_HANDLE_VALUE;
		Tcl_Obj *result = Tcl_NewStringObj("", -1);
		Tcl_SetObjResult(interp, result);
		return TCL_OK;
	}

	Tcl_Obj *resultList = read_win32_find_data(interp, &dexfex_xfd);
	Tcl_SetObjResult(interp, resultList);
	return TCL_OK;
}



// ==title== dexfend end







int BlocksNewCmd(ClientData clientdata, Tcl_Interp *interp,
				int argc, char *argv[])
{

	char blocks_handle[16 + TCL_INTEGER_SPACE];
	
	Tcl_HashEntry *hash_entry;
	int hash_new_ptr;

	blocks_finder *finder;

	Tcl_DString ds_dir;

	if (argc != 2) {
		interp->result = "whoa! usage: blocks_new dir";
		return TCL_ERROR;
	}
	
	sprintf(blocks_handle, "blocks%d", blocks_handle_count++);

	
	hash_entry = Tcl_CreateHashEntry(&blocks_hash, blocks_handle, &hash_new_ptr);

	finder = (blocks_finder *)ckalloc(sizeof(blocks_finder));

	Tcl_SetHashValue(hash_entry, finder);

	finder->first_time = 1;



	//finder->dir = (char *)ckalloc(strlen(argv[1])+1);
	//strcpy(finder->dir, argv[1]);

	Tcl_UtfToExternalDString(NULL,	argv[1], strlen(argv[1]), &ds_dir);

	finder->dir = (char *)ckalloc( Tcl_DStringLength(&ds_dir) + 1 );
	strcpy(finder->dir, Tcl_DStringValue(&ds_dir));

	Tcl_DStringFree(&ds_dir);



	// deprecated, doesn't work in 8.3.5 and 8.5a4
	//interp->result = blocks_handle;
	Tcl_SetResult(interp, blocks_handle, TCL_VOLATILE);

	return TCL_OK;
}


void BlocksClean(Tcl_HashEntry *hash_entry, blocks_finder *finder)
{
	if (finder->h != INVALID_HANDLE_VALUE) {
		FindClose(finder->h);
	}
	ckfree(finder->dir);
	ckfree((char *)finder);
	Tcl_DeleteHashEntry(hash_entry);
	return;
}


int BlocksDelCmd(ClientData clientdata, Tcl_Interp *interp,
				int argc, char *argv[])
{
	char *blocks_handle;

	Tcl_HashEntry *hash_entry;

	blocks_finder *finder;

	if (argc != 2) {
		interp->result = "oops! usage: blocks_del handle";
		return TCL_ERROR;
	}

	blocks_handle = argv[1];

	hash_entry = Tcl_FindHashEntry(&blocks_hash, blocks_handle);

	if (hash_entry != NULL) {
		finder = (blocks_finder *)Tcl_GetHashValue(hash_entry);
		BlocksClean(hash_entry, finder);
	} else {
		interp->result = "no handle by thar name matey!";
		return TCL_ERROR;
	}

	return TCL_OK;
}


int BlocksGetCmd(ClientData clientdata, Tcl_Interp *interp,
				int argc, char *argv[])
{

	char *blocks_handle;

	Tcl_HashEntry *hash_entry;

	blocks_finder *finder;

	Tcl_DString ds_filename;

	LARGE_INTEGER timex;
	char time_t_buffer[20];

	LARGE_INTEGER xxsize;
	char size_buffer[66];

	char attrib[5];  // rhsa + null


	if (argc != 2) {
		interp->result = "bad! usage: blocks_get handle";
		return TCL_ERROR;
	}

	blocks_handle = argv[1];

	hash_entry = Tcl_FindHashEntry(&blocks_hash, blocks_handle);
	if (hash_entry == NULL) {
		interp->result = "no way that handle exists bucko";
		return TCL_ERROR;
	}

	finder = (blocks_finder *)Tcl_GetHashValue(hash_entry);

	if (finder->first_time) {
		finder->first_time = 0;

		finder->h = FindFirstFile(finder->dir, &finder->data);
		if (finder->h == INVALID_HANDLE_VALUE) {
			BlocksClean(hash_entry, finder);
			interp->result = "";
			return TCL_OK;
		}
		
	} else {

		if (!FindNextFile(finder->h, &finder->data)) {
			BlocksClean(hash_entry, finder);
			interp->result = "";
			return TCL_OK;
		}

	}
	

	//
	// filename
	//

	// new utf string from win32 filename, pass it to tcl, free it

	Tcl_ExternalToUtfDString(NULL, finder->data.cFileName, strlen(finder->data.cFileName),	&ds_filename);
	Tcl_AppendElement(interp, Tcl_DStringValue(&ds_filename));
	Tcl_DStringFree(&ds_filename);


	
	//
	// directory or file
	//

	if (finder->data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
		Tcl_AppendElement(interp, "d");
	} else {
		Tcl_AppendElement(interp, "f");
	}



	//
	// mtime
	//

	// timex can be used as a 64bit int (timex.QuadPart)
	timex.HighPart = finder->data.ftLastWriteTime.dwHighDateTime;
	timex.LowPart  = finder->data.ftLastWriteTime.dwLowDateTime;
	// had to add 'LLU' so mingw would compile without a warning (unsigned long long)
	timex.QuadPart = (timex.QuadPart - 116444736000000000LLU) / 10000000;
	// timex.LowPart now contains time_t

	_itoa(timex.LowPart, time_t_buffer, 10);
	Tcl_AppendElement(interp, time_t_buffer);


	//
	// size
	//

	// only use the low dword, so max filesize is going to be 2^32 = 4 GB
	//_itoa(finder->data.nFileSizeLow, size_buffer, 10);
	//Tcl_AppendElement(interp, size_buffer);

	// use the entire 64bit
	xxsize.LowPart  = finder->data.nFileSizeLow;
	xxsize.HighPart = finder->data.nFileSizeHigh;
	_i64toa(xxsize.QuadPart, size_buffer, 10);  // base 10
	Tcl_AppendElement(interp, size_buffer);




	//
	// rhsa attributes
	//

	strcpy(attrib, "");
	if (finder->data.dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
		strcat(attrib, "r");
	}
	if (finder->data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) {
		strcat(attrib, "h");
	}
	if (finder->data.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) {
		strcat(attrib, "s");
	}
	if (finder->data.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) {
		strcat(attrib, "a");
	}
	Tcl_AppendElement(interp, attrib);



	return TCL_OK;
}

