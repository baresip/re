struct odict_entry {
	struct le le, he;
	char *key;
	union {
		struct odict *odict;   /* ODICT_OBJECT / ODICT_ARRAY */
		char *str;             /* ODICT_STRING */
		int64_t integer;       /* ODICT_INT    */
		double dbl;            /* ODICT_DOUBLE */
		bool boolean;          /* ODICT_BOOL   */
	} u;
	enum odict_type type;
};
