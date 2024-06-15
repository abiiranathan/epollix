use mime::Mime;
use multipart::server::Multipart;
use std::ffi::{CStr, CString};
use std::io::Read;
use std::os::raw::c_char;

/// Represents a form data with fields and files.
#[repr(C)]
#[derive(Debug)]
pub struct FormData {
    fields: *mut FormField,    // Array of fields in the form data.
    field_count: usize,        // Number of fields in the form data.
    files: *mut MultipartFile, // Array of files in the form data.
    file_count: usize,         // Number of files in the form data.
}

/// Represents a file with filename, content type, content, and content length.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct MultipartFile {
    filename: *const c_char,     // Filename of the file.
    content_type: *const c_char, // Content type of the file.
    content: *mut u8,            // Raw bytes of the file content.
    content_length: usize,       // Length of the file content in bytes.
    field_name: *const c_char,   // Name of the field that the file is associated with.
}

/// Represents a field with name and value.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct FormField {
    name: *const c_char,
    value: *const c_char,
}

/// Parses the multipart form data from the given body.
/// Returns a pointer to the parsed form data. If the body is null, returns a pointer to an empty form data.
/// Likewise if the boundary is not found, returns a pointer to an empty form data that must be freed.
/// The caller is responsible for freeing the form data by calling `free_multipart_form_data`.
#[no_mangle]
pub extern "C" fn parse_multipart_form_data(body: *const c_char) -> *mut FormData {
    if body.is_null() {
        return Box::into_raw(Box::new(FormData {
            fields: std::ptr::null_mut(),
            field_count: 0,
            files: std::ptr::null_mut(),
            file_count: 0,
        }));
    }

    // Convert the C string to a Rust string.
    let body_cstr = unsafe { CStr::from_ptr(body) };
    let body_str = body_cstr.to_str().unwrap();

    let mut fields: Vec<FormField> = Vec::new();
    let mut files: Vec<MultipartFile> = Vec::new();

    // Extract the boundary, find the first occurrence of '\r\n' in the body.
    let boundary_index = body_str.find("\r\n");
    let boundary_str = match boundary_index {
        Some(index) => &body_str[2..index],
        None => {
            eprintln!("Failed to find boundary in multipart form data");
            return Box::into_raw(Box::new(FormData {
                fields: std::ptr::null_mut(),
                field_count: 0,
                files: std::ptr::null_mut(),
                file_count: 0,
            }));
        }
    };

    let mut data = body_str.as_bytes();

    // Parse the multipart form data.
    let mut multipart = Multipart::with_body(&mut data, boundary_str);

    // Iterate over each entry in the multipart form data.
    if let Err(e) = multipart.foreach_entry(|mut entry| {
        let mut content: Vec<u8> = Vec::new();
        entry.data.read_to_end(&mut content).unwrap();

        if let Some(filename) = &entry.headers.filename {
            let content_type = entry
                .headers
                .content_type
                .clone()
                .unwrap_or_else(|| "application/octet-stream".parse::<Mime>().unwrap());

            let content_length = content.len();

            let content_ptr = content.as_mut_ptr();
            std::mem::forget(content);

            files.push(MultipartFile {
                filename: CString::new(filename.clone()).unwrap().into_raw(),
                content_type: CString::new(content_type.to_string()).unwrap().into_raw(),
                content: content_ptr,
                content_length,
                field_name: CString::new(entry.headers.name.to_string())
                    .unwrap()
                    .into_raw(),
            });
        } else {
            fields.push(FormField {
                name: CString::new(entry.headers.name.to_string())
                    .unwrap()
                    .into_raw(),
                value: CString::new(String::from_utf8(content).unwrap())
                    .unwrap()
                    .into_raw(),
            });
        }
    }) {
        eprintln!("Failed to parse multipart form data: {}", e);
    }

    // Convert vectors into boxed slices and get raw pointers.
    let fields_slice = fields.into_boxed_slice();
    let files_slice = files.into_boxed_slice();

    let form_data = FormData {
        fields: fields_slice.as_ptr() as *mut FormField,
        field_count: fields_slice.len() as usize,
        files: files_slice.as_ptr() as *mut MultipartFile,
        file_count: files_slice.len(),
    };

    // Prevent the boxed slices from being deallocated.
    std::mem::forget(fields_slice);
    std::mem::forget(files_slice);

    Box::into_raw(Box::new(form_data))
}

/// Frees the given form data. If the form data is null, does nothing.
#[no_mangle]
pub extern "C" fn free_multipart_form_data(data: *mut FormData) {
    if data.is_null() {
        return;
    }

    let data = unsafe { Box::from_raw(data) };

    // Free the fields
    for i in 0..data.field_count {
        let field = unsafe { &*data.fields.add(i) };
        unsafe {
            let _ = CString::from_raw(field.name as *mut c_char);
            let _ = CString::from_raw(field.value as *mut c_char);
        }
    }

    // Free the fields array
    if !data.fields.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(data.fields, data.field_count, data.field_count);
        }
    }

    // Free the files
    for i in 0..data.file_count {
        let file = unsafe { &*data.files.add(i) };
        unsafe {
            let _ = CString::from_raw(file.filename as *mut c_char);
            let _ = CString::from_raw(file.content_type as *mut c_char);
            let _ = CString::from_raw(file.field_name as *mut c_char);
            let _ = Vec::from_raw_parts(file.content, file.content_length, file.content_length);
        }
    }

    // Free the files array
    if !data.files.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(data.files, data.file_count, data.file_count);
        }
    }
}
