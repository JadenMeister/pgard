<!-- corpus: expect=PG-XSS-003 -->
<template>
  <div v-for="DOMPurify in helpers" :key="DOMPurify.id">
    <span v-html="DOMPurify.sanitize(html)"></span>
  </div>
</template>
<script setup>
import DOMPurify from "dompurify";
defineProps({ html: String, helpers: Array });
</script>
