<!-- corpus: expect=PG-XSS-003 -->
<template><div v-html="xssFilters.inDoubleQuotedAttr($route.query.q)"></div></template>
<script setup>
import xssFilters from "xss-filters";
</script>
