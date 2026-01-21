use wasmer::wasmparser::{
    Export, Import, MemoryType, Parser, Payload, TableType, Type, ValidPayload, Validator,
    WasmFeatures,
};

use crate::VmResult;

/// A parsed and validated wasm module.
/// It keeps track of the parts that are important for our static analysis and compatibility checks.
#[derive(Debug)]
pub struct ParsedWasm<'a> {
    pub version: u32,
    pub exports: Vec<Export<'a>>,
    pub imports: Vec<Import<'a>>,
    pub tables: Vec<TableType>,
    pub memories: Vec<MemoryType>,
    pub function_count: usize,
    pub type_count: u32,
    pub max_func_params: usize,
    pub max_func_results: usize,
}

impl<'a> ParsedWasm<'a> {
    pub fn parse(wasm: &'a [u8]) -> VmResult<Self> {
        let mut validator = Validator::new_with_features(WasmFeatures {
            mutable_global: true,
            saturating_float_to_int: true,
            sign_extension: true,
            multi_value: true,
            deterministic_only: true,
            // IMPORTANT: reference_types must be enabled at the PARSING layer for Rust 1.82+ compatibility.
            //
            // Rust 1.82+ emits call_indirect with a multi-byte LEB128 table index (e.g., 0x80 0x00)
            // instead of the single-byte 0x00 required by MVP. Both encode table index 0, but
            // wasmparser ≥0.95 rejects multi-byte encodings when reference_types is disabled.
            //
            // This is a BINARY ENCODING issue, not a feature usage issue - contracts compiled with
            // Rust 1.82+ will fail validation even if they use zero reference-types features.
            //
            // Security: Enabling reference_types here only affects parsing/validation. Dangerous
            // instructions (table.grow, table.fill, etc.) are blocked separately by the Gatekeeper
            // middleware which runs after parsing.
            reference_types: true,
            bulk_memory: false,
            simd: false,
            relaxed_simd: false,
            threads: false,
            tail_call: false,
            multi_memory: false,
            exceptions: false,
            memory64: false,
            extended_const: false,
            component_model: false,
        });

        let mut this = Self {
            version: 0,
            exports: vec![],
            imports: vec![],
            tables: vec![],
            memories: vec![],
            function_count: 0,
            type_count: 0,
            max_func_params: 0,
            max_func_results: 0,
        };

        let mut fun_allocations = Default::default();
        for p in Parser::new(0).parse_all(wasm) {
            let p = p?;
            // validate the payload
            if let ValidPayload::Func(fv, body) = validator.payload(&p)? {
                // also validate function bodies
                let mut fun_validator = fv.into_validator(fun_allocations);
                fun_validator.validate(&body)?;
                fun_allocations = fun_validator.into_allocations();

                this.function_count += 1;
            }

            match p {
                Payload::TypeSection(t) => {
                    this.type_count = t.get_count();
                    for t_res in t {
                        let ty: Type = t_res?;
                        match ty {
                            Type::Func(ft) => {
                                this.max_func_params =
                                    core::cmp::max(ft.params().len(), this.max_func_params);
                                this.max_func_results =
                                    core::cmp::max(ft.results().len(), this.max_func_results);
                            }
                        }
                    }
                }
                Payload::Version { num, .. } => this.version = num,
                Payload::ImportSection(i) => {
                    this.imports = i.into_iter().collect::<Result<Vec<_>, _>>()?;
                }
                Payload::TableSection(t) => {
                    this.tables = t.into_iter().collect::<Result<Vec<_>, _>>()?;
                }
                Payload::MemorySection(m) => {
                    this.memories = m.into_iter().collect::<Result<Vec<_>, _>>()?;
                }
                Payload::ExportSection(e) => {
                    this.exports = e.into_iter().collect::<Result<Vec<_>, _>>()?;
                }
                _ => {} // ignore everything else
            }
        }

        Ok(this)
    }
}
