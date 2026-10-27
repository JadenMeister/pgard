<!-- corpus: expect=low -->
<template>
  <div v-html="DOMPurify.sanitize(html)"></div>
</template>
<script setup>
import DOMPurify from "dompurify";
defineProps({ html: String });

function preview(DOMPurify) {
  return DOMPurify;
}
</script>
