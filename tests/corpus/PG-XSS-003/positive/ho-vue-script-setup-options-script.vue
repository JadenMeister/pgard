<!-- corpus: expect=PG-XSS-003 -->
<template>
  <div v-html="DOMPurify.sanitize(html, purifyOptions)"></div>
</template>
<script setup>
import DOMPurify from "dompurify";
defineProps({ html: String });
const purifyOptions = { ADD_TAGS: ["script"] };
</script>
