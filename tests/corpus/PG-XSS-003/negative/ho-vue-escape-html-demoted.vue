<!-- corpus: expect=low -->
<template>
  <div v-html="escapeHtml(html)"></div>
</template>
<script setup>
import escapeHtml from "escape-html";
defineProps({ html: String });
</script>
