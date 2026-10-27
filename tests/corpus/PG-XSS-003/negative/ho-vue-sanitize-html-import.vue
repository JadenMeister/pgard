<!-- corpus: expect=none -->
<template>
  <div v-html="sanitizeHtml(html)"></div>
</template>
<script setup>
import sanitizeHtml from "sanitize-html";
defineProps({ html: String });
</script>
