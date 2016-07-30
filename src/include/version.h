
#if !defined(_LRD_VERSION_STRING)
	#error "error: undefined development version - please define via build system"
#endif

//the component value should not change
#define DCAS_LAIRD_COMPONENT    92

//the next three values define the API version between DCAL and DCAS
#define LAIRD_SDK_MSB       3
#define LAIRD_DCAS_MAJOR    1
#define LAIRD_DCAS_MINOR    1

// the following #DEFINES should not be modified by hand
// -----------------------------------------------------
#define STR_VALUE(arg) #arg
#define ZVER(name) STR_VALUE(name)

#define DCAL_VERSION_STR ZVER(LAIRD_SDK_MSB) "." ZVER(LAIRD_DCAS_MAJOR) "." ZVER(LAIRD_DCAS_MINOR)
#define DCAL_VERSION ((LAIRD_SDK_MSB << 16) | (LAIRD_DCAS_MAJOR << 8) | LAIRD_DCAS_MINOR)
#define DCAS_COMPONENT_VERSION ((DCAS_LAIRD_COMPONENT << 24) | (LAIRD_SDK_MSB << 16) | (LAIRD_DCAS_MAJOR << 8) | LAIRD_DCAS_MINOR)
// -----------------------------------------------------
