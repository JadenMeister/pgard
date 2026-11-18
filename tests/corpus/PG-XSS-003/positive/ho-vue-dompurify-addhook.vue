<!-- corpus: expect=PG-XSS-003 -->
<template>
  <div v-html="DOMPurify.sanitize(html)"></div>
</template>
<script setup>
import DOMPurify from "dompurify";
defineProps({ html: String });
DOMPurify.addHook("uponSanitizeElement", (node) => node);
</script>
