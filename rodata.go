package libbpfgo

/*
static bool str_has_suffix(const char *str, const char *suffix)
{
	size_t i, n1 = strlen(str), n2 = strlen(suffix);

	if (n1 < n2)
		return false;

	for (i = 0; i < n2; i++) {
		if (str[n1 - i - 1] != suffix[n2 - i - 1])
			return false;
	}

	return true;
}

static const char *get_map_ident(const struct bpf_map *map)
{
	const char *name = bpf_map__name(map);

	if (!bpf_map__is_internal(map))
		return name;

	if (str_has_suffix(name, ".data"))
		return "data";
	else if (str_has_suffix(name, ".rodata"))
		return "rodata";
	else if (str_has_suffix(name, ".bss"))
		return "bss";
	else if (str_has_suffix(name, ".kconfig"))
		return "kconfig";
	else
		return NULL;
}

struct bpf_map* get_ro_map(struct bpf_object* obj)
{
	struct bpf_map *map;
	const char* ident;

	bpf_object__for_each_map(map, obj) {
		if (bpf_map__is_internal(map)) {
			ident = get_map_ident(map);
			if (strcmp(ident, "rodata") == 0) {
				return map;
			}
		}
	}
	return NULL;
}
*/
import "C"
import "errors"

func (m *Module) GetRODataMap() (*BPFMap, error) {
	if m.obj == nil {
		return errors.New("unitialized bpf object")
	}

	roMap := C.get_ro_map(m.obj)
	if roMap == nil {
		return nil, errors.New("could not find .rodata map")
	}

	return &BPFMap{
		name:     ".rodata",
		bpfMap:   roMap,
		fd:       C.bpf_map__fd(bpfMap), // Is having an fd accurate here??
		module:   m,
		readonly: true,
	}, nil
}

func (ro *BPFMap) UpdateReadonly() {

}
